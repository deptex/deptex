package files

import "os"

// Server-side allow-list of paths. The handler can only access paths the
// developer registered here — there is no string path coming from the
// request, so the os.ReadFile sink receives only constant input.
var catalog = []string{
	"./assets/0.bin",
	"./assets/1.bin",
}

func ReadByID(id int) ([]byte, error) {
	if id < 0 || id >= len(catalog) {
		id = 0
	}
	return os.ReadFile(catalog[id])
}
