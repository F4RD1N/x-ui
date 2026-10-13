package hw

// SplitHow is SplitCPUs plus how the auto instances were split ("node",
// "package", "cut", "shared" or ""), for the tests of package hw_test.
func SplitHow(t *Topology, cpus []int, prefer int, reqs []CPURequest, less func(a, b string) bool) (map[string][]int, string) {
	return split(t, cpus, prefer, reqs, less)
}
