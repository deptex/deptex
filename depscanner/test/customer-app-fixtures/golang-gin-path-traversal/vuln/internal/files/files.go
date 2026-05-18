package files

import "os"

// Read opens a user-supplied path — classic path-traversal sink
// (os.ReadFile is registered as a path_traversal sink in go-stdlib.yaml).
func Read(name string) ([]byte, error) {
	return os.ReadFile(name)
}
