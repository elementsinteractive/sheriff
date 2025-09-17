package compress

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTarGz extracts a tar.gz archive to the specified destination directory.
func ExtractTarGz(reader io.Reader, destDir string) error {
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip the root directory (GitLab archives have a root folder)
		pathParts := strings.Split(header.Name, "/")
		if len(pathParts) <= 1 {
			continue
		}

		// Remove the first directory component (the root folder)
		relativePath := strings.Join(pathParts[1:], "/")
		if relativePath == "" {
			continue
		}

		targetPath := filepath.Join(destDir, relativePath)
		if !strings.HasPrefix(targetPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("content of tar file is trying to write outside of destination directory: %s", relativePath)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", targetPath, err)
			}

			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}
			defer file.Close()

			if _, err := io.Copy(file, tarReader); err != nil {
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
		}
	}

	return nil
}
