// Package hw reads what x-ui needs to know about the machine's hardware: the
// CPU topology (packages, NUMA nodes, cores and their threads), the network
// devices under the default routes (driver, NUMA node, queues, interrupts,
// RSS, XPS and RPS), the ethtool settings of those devices, and the
// instances.json file the panel writes for "x-ui tune nic" and "x-ui diag".
//
// It only reads. It never writes a kernel file and runs no external command;
// every change to the kernel is made by util/tune. The ethtool interface has
// setters for util/tune's use, but nothing in this package calls them.
//
// Every file is read below an FS root, so tests run against fake /sys and
// /proc trees (see the hwtest package). The environment variable
// XUI_HW_ROOT=<dir> points EnvFS at such a tree; it is for tests only.
package hw
