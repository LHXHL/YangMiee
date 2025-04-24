// web/embed.go
package web

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed dist
var staticFiles embed.FS

// GetStaticFS 返回嵌入式文件系统
func GetStaticFS() fs.FS {
	distFS, _ := fs.Sub(staticFiles, "dist")
	return distFS
}

// CopyToLocalFS 将嵌入的资源文件提取到本地文件系统
func CopyToLocalFS(targetDir string) error {
	// 确保目标目录存在
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}

	// 遍历嵌入的文件系统
	return fs.WalkDir(staticFiles, "dist", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// 计算目标路径
		relPath, err := filepath.Rel("dist", path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(targetDir, relPath)

		// 处理目录
		if d.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}

		// 处理文件
		data, err := staticFiles.ReadFile(path)
		if err != nil {
			return err
		}

		// 写入文件
		return os.WriteFile(targetPath, data, 0644)
	})
}
