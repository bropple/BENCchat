//go:build linux

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// installDesktopEntry writes a freedesktop .desktop file and a themed icon into
// the user's local data dir, so KDE/GNOME can resolve BENCchat's window and
// taskbar icon to the R. Triy mark.
//
// This is needed because on a Wayland session the X11 _NET_WM_ICON that
// gtk_window_set_icon sets is ignored — the compositor matches the window's
// app-id ("benchat", set via ProgramName) to an installed desktop entry and
// takes the icon from there. Writing the entry also fixes the taskbar icon and
// window grouping on X11. Best-effort and idempotent: any failure just leaves
// the default icon in place and is logged, never fatal.
func (a *App) installDesktopEntry() {
	if len(a.desktopIcon) == 0 {
		return
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			slog.Default().Warn("desktop entry: no home dir", "err", err)
			return
		}
		dataHome = filepath.Join(home, ".local", "share")
	}

	// Themed icon: hicolor/512x512/apps/benchat.png (our appicon is 512×512).
	iconDir := filepath.Join(dataHome, "icons", "hicolor", "512x512", "apps")
	if err := os.MkdirAll(iconDir, 0o755); err != nil {
		slog.Default().Warn("desktop entry: mkdir icon dir", "err", err)
		return
	}
	iconPath := filepath.Join(iconDir, "benchat.png")
	if err := os.WriteFile(iconPath, a.desktopIcon, 0o644); err != nil {
		slog.Default().Warn("desktop entry: write icon", "err", err)
		return
	}

	exe, err := os.Executable()
	if err != nil {
		slog.Default().Warn("desktop entry: executable path", "err", err)
		return
	}

	appDir := filepath.Join(dataHome, "applications")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		slog.Default().Warn("desktop entry: mkdir applications", "err", err)
		return
	}
	// StartupWMClass must match the app-id set via linux.Options.ProgramName so
	// the compositor associates the running window with this entry's icon.
	entry := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=BENCchat
GenericName=Instant Messenger
Comment=A modern OSCAR/AIM client for the BENCO network
Exec=%s
Icon=benchat
Terminal=false
Categories=Network;InstantMessaging;
StartupWMClass=benchat
`, exe)
	entryPath := filepath.Join(appDir, "benchat.desktop")
	if err := os.WriteFile(entryPath, []byte(entry), 0o644); err != nil {
		slog.Default().Warn("desktop entry: write .desktop", "err", err)
	}
}
