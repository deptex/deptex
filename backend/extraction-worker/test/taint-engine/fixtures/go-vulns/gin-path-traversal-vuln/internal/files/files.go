package files

import "os"

// Read opens a user-supplied path — classic path traversal.
func Read(path string) ([]byte, error) {
	return os.ReadFile(path)
}
