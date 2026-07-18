//go:build !linux

package main

// installDesktopEntry is a no-op off Linux: Windows takes its icon from the
// compiled-in .ico and macOS from the .app bundle, so neither needs a desktop
// entry written at runtime.
func (a *App) installDesktopEntry() {}
