// Package tray shows a system-tray (notification-area) icon so BENCchat keeps
// running when its window is closed, the way a desktop chat client does.
//
// It wraps fyne.io/systray. That library's Linux/BSD backend speaks the
// StatusNotifierItem D-Bus spec — the same protocol KDE and GNOME shell trays
// use — with no cgo or GTK dependency, so it cross-compiles like the rest of the
// client. On Windows it drives the notification area directly. macOS requires
// the tray loop to own the main thread, which conflicts with Wails, so the tray
// is only started on Windows and Linux (see Start's caller).
package tray

import (
	"runtime"

	"fyne.io/systray"
)

// Handlers are the app actions the tray menu triggers. Either may be nil.
type Handlers struct {
	OnShow func() // bring the window back to the foreground
	OnQuit func() // really exit the application
}

// Icons holds the platform-native icon bytes for both tray states. PNG is used
// on Linux/macOS, ICO on Windows.
type Icons struct {
	NormalPNG, NormalICO []byte
	BadgePNG, BadgeICO   []byte
}

// Tray is a running tray icon. Use SetBadge to switch between the plain and
// notification (dotted) icon, and Stop to remove it.
type Tray struct {
	icons Icons
	stop  func()
}

// Start launches the tray icon on a background loop. Call Stop on shutdown.
func Start(icons Icons, h Handlers) *Tray {
	t := &Tray{icons: icons}
	onReady := func() {
		t.applyIcon(false)
		systray.SetTitle("BENCchat")
		systray.SetTooltip("BENCchat")

		mOpen := systray.AddMenuItem("Open BENCchat", "Show the BENCchat window")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit BENCchat", "Exit BENCchat")

		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					if h.OnShow != nil {
						h.OnShow()
					}
				case <-mQuit.ClickedCh:
					if h.OnQuit != nil {
						h.OnQuit()
					}
					return
				}
			}
		}()
	}
	// RunWithExternalLoop starts the tray without taking over this goroutine, so
	// it lives alongside the Wails event loop.
	start, end := systray.RunWithExternalLoop(onReady, nil)
	start()
	t.stop = end
	return t
}

// SetBadge switches the tray icon to the notification (dotted) variant when on,
// or back to the plain mark when off. Safe to call from any goroutine.
func (t *Tray) SetBadge(on bool) {
	if t == nil {
		return
	}
	t.applyIcon(on)
}

// applyIcon sets the platform-appropriate icon bytes for the requested state.
func (t *Tray) applyIcon(badge bool) {
	windows := runtime.GOOS == "windows"
	var b []byte
	switch {
	case badge && windows:
		b = t.icons.BadgeICO
	case badge:
		b = t.icons.BadgePNG
	case windows:
		b = t.icons.NormalICO
	default:
		b = t.icons.NormalPNG
	}
	if len(b) > 0 {
		systray.SetIcon(b)
	}
}

// Stop removes the tray icon.
func (t *Tray) Stop() {
	if t != nil && t.stop != nil {
		t.stop()
		t.stop = nil
	}
}
