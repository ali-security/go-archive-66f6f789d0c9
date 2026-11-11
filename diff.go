package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containerd/log"

	"github.com/moby/go-archive/compression"
)

// UnpackLayer unpack `layer` to a `dest`. The stream `layer` can be
// compressed or uncompressed.
// Returns the size in bytes of the contents of the layer.
func UnpackLayer(dest string, layer io.Reader, options *TarOptions) (size int64, err error) {
	tr := tar.NewReader(layer)

	var dirs []unpackedDir
	// unpackedPaths tracks the resolved filesystem paths already written in
	// this layer so that the AUFS opaque-whiteout walk knows which paths to
	// preserve.
	unpackedPaths := make(map[string]struct{})

	if options == nil {
		options = &TarOptions{}
	}
	if options.ExcludePatterns == nil {
		options.ExcludePatterns = []string{}
	}

	aufsTempdir := ""
	aufsHardlinks := make(map[string]*tar.Header)

	// Iterate through the files in the archive.
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			// end of tar archive
			break
		}
		if err != nil {
			return 0, err
		}

		size += hdr.Size

		// Strip a leading "/" so absolute entries stay root-relative, and
		// normalize the POSIX tar path. Skip entries referring to the extraction
		// root and reject paths that escape it.
		name := path.Clean(strings.TrimLeft(hdr.Name, "/"))
		if name == "." {
			continue
		}

		// Skip entries whose name (or hardlink target) Windows cannot represent.
		if err := unrepresentableOnWindows(name, hdr); err != nil {
			log.G(context.TODO()).Warnf("Windows: ignoring entry: %v", err)
			continue
		}
		if !filepath.IsLocal(name) {
			return 0, breakoutError(fmt.Errorf("invalid entry name %q", hdr.Name))
		}
		hdr.Name = name

		// Skip AUFS metadata dirs
		if strings.HasPrefix(hdr.Name, WhiteoutMetaPrefix) {
			// Regular files inside /.wh..wh.plnk can be used as hardlink targets
			// We don't want this directory, but we need the files in them so that
			// such hardlinks can be resolved.
			if strings.HasPrefix(hdr.Name, WhiteoutLinkDir) && hdr.Typeflag == tar.TypeReg {
				basename := path.Base(hdr.Name)
				aufsHardlinks[basename] = hdr
				if aufsTempdir == "" {
					if aufsTempdir, err = os.MkdirTemp(dest, "dockerplnk"); err != nil {
						return 0, err
					}
					defer os.RemoveAll(aufsTempdir)
				}
				if err := createTarFile(aufsTempdir, basename, hdr, tr, options); err != nil {
					return 0, err
				}
			}

			if hdr.Name != WhiteoutOpaqueDir {
				continue
			}
		}

		// dstPath is the native (host-separator), root-relative form of the
		// entry name, with any symlinks in its parent directories resolved
		// within dest. The tar-header name (hdr.Name) is POSIX, so convert it here.
		dstPath, err := resolveArchivePath(dest, filepath.FromSlash(hdr.Name))
		if err != nil {
			return 0, err
		}
		// Ensure that the parent directory exists.
		if err := createImpliedDirectories(dest, dstPath, options); err != nil {
			return 0, err
		}
		dst := filepath.Join(dest, dstPath)

		if base := filepath.Base(dst); strings.HasPrefix(base, WhiteoutPrefix) {
			dir := filepath.Dir(dst)
			if base == WhiteoutOpaqueDir {
				_, err := os.Lstat(dir)
				if err != nil {
					return 0, err
				}
				// dir was resolved within dest, and WalkDir does not follow
				// symlinks, so the walk (and removal) stays within dest.
				err = filepath.WalkDir(dir, func(p string, info os.DirEntry, err error) error {
					if err != nil {
						if os.IsNotExist(err) {
							err = nil // parent was deleted
						}
						return err
					}
					if p == dir {
						return nil
					}
					// unpackedPaths is keyed by resolved filesystem paths,
					// matching filepath.WalkDir's paths.
					if _, exists := unpackedPaths[p]; !exists {
						return os.RemoveAll(p)
					}
					return nil
				})
				if err != nil {
					return 0, err
				}
			} else {
				originalBase := base[len(WhiteoutPrefix):]
				// A whiteout must name an entry inside dir; reject whiteouts
				// that would remove dir itself or its parent.
				if originalBase == "" || originalBase == "." || originalBase == ".." {
					return 0, breakoutError(fmt.Errorf("invalid whiteout entry %q", hdr.Name))
				}
				originalPath := filepath.Join(dir, originalBase)
				if err := os.RemoveAll(originalPath); err != nil {
					return 0, err
				}
			}
		} else {
			// If dst exists we almost always just want to remove and replace it.
			// The only exception is when it is a directory *and* the file from
			// the layer is also a directory. Then we want to merge them (i.e.
			// just apply the metadata from the layer).
			if fi, err := os.Lstat(dst); err == nil {
				if !fi.IsDir() || hdr.Typeflag != tar.TypeDir {
					if err := os.RemoveAll(dst); err != nil {
						return 0, err
					}
				}
			}

			srcData := io.Reader(tr)
			srcHdr := hdr

			// Hard links into /.wh..wh.plnk don't work, as we don't extract that directory, so
			// we manually retarget these into the temporary files we extracted them into
			if hdr.Typeflag == tar.TypeLink && strings.HasPrefix(path.Clean(hdr.Linkname), WhiteoutLinkDir) {
				linkBasename := path.Base(hdr.Linkname)
				srcHdr = aufsHardlinks[linkBasename]
				if srcHdr == nil {
					return 0, errors.New("invalid aufs hardlink")
				}
				tmpFile, err := os.Open(filepath.Join(aufsTempdir, linkBasename))
				if err != nil {
					return 0, err
				}
				defer tmpFile.Close()
				srcData = tmpFile
			}

			if err := remapIDs(options.IDMap, srcHdr); err != nil {
				return 0, err
			}

			if err := createTarFile(dest, dstPath, srcHdr, srcData, options); err != nil {
				return 0, err
			}

			// Directory mtimes must be handled at the end to avoid further
			// file creation in them to modify the directory mtime
			if hdr.Typeflag == tar.TypeDir {
				dirs = append(dirs, unpackedDir{hdr: hdr, name: dstPath})
			}
			unpackedPaths[dst] = struct{}{}
		}
	}

	for _, d := range dirs {
		if err := chtimesInRoot(dest, d.name, d.hdr.AccessTime, d.hdr.ModTime); err != nil {
			return 0, err
		}
	}

	return size, nil
}

// ApplyLayer parses a diff in the standard layer format from `layer`,
// and applies it to the directory `dest`. The stream `layer` can be
// compressed or uncompressed.
// Returns the size in bytes of the contents of the layer.
func ApplyLayer(dest string, layer io.Reader) (int64, error) {
	return applyLayerHandler(dest, layer, &TarOptions{}, true)
}

// ApplyUncompressedLayer parses a diff in the standard layer format from
// `layer`, and applies it to the directory `dest`. The stream `layer`
// can only be uncompressed.
// Returns the size in bytes of the contents of the layer.
func ApplyUncompressedLayer(dest string, layer io.Reader, options *TarOptions) (int64, error) {
	return applyLayerHandler(dest, layer, options, false)
}

// IsEmpty checks if the tar archive is empty (doesn't contain any entries).
func IsEmpty(rd io.Reader) (bool, error) {
	decompRd, err := compression.DecompressStream(rd)
	if err != nil {
		return true, fmt.Errorf("failed to decompress archive: %w", err)
	}
	defer decompRd.Close()

	tarReader := tar.NewReader(decompRd)
	if _, err := tarReader.Next(); err != nil {
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return false, fmt.Errorf("failed to read next archive header: %w", err)
	}

	return false, nil
}

// do the bulk load of ApplyLayer, but allow for not calling DecompressStream
func applyLayerHandler(dest string, layer io.Reader, options *TarOptions, decompress bool) (int64, error) {
	dest = filepath.Clean(dest)

	// We need to be able to set any perms
	restore := overrideUmask(0)
	defer restore()

	if decompress {
		decompLayer, err := compression.DecompressStream(layer)
		if err != nil {
			return 0, err
		}
		defer decompLayer.Close()
		layer = decompLayer
	}
	return UnpackLayer(dest, layer, options)
}
