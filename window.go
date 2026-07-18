package main

import (
	"context"
	stdruntime "runtime"

	"github.com/benco-holdings/benchat/internal/config"
	"github.com/benco-holdings/benchat/internal/tray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// startTray brings up the system-tray icon, so closing the window hides BENCchat
// to the tray instead of quitting it. Called from startup once the Wails context
// exists. Skipped on macOS (its tray backend needs the main thread, which Wails
// owns) and when no icon was injected.
func (a *App) startTray() {
	if stdruntimeGOOSIsDarwin() || a.trayIcons.NormalPNG == nil {
		return
	}
	a.tray = tray.Start(a.trayIcons, tray.Handlers{
		OnShow: a.showWindow,
		OnQuit: a.quitApp,
	})
}

// stopTray removes the tray icon on shutdown.
func (a *App) stopTray() {
	a.tray.Stop()
	a.tray = nil
}

// SetTrayNotify toggles the tray's notification dot. The frontend calls this when
// unread messages arrive while the window is unfocused/hidden, and clears it when
// the window regains focus. Bound into JS.
func (a *App) SetTrayNotify(on bool) {
	a.tray.SetBadge(on)
}

// MinimizeWindow / ToggleMaximiseWindow / CloseWindow drive the custom titlebar's
// controls when the frameless (custom-frame) window is in use. CloseWindow mirrors
// the native close button: hide to the tray if it's up, otherwise really quit.
func (a *App) MinimizeWindow() {
	if a.ctx != nil {
		runtime.WindowMinimise(a.ctx)
	}
}

func (a *App) ToggleMaximiseWindow() {
	if a.ctx != nil {
		runtime.WindowToggleMaximise(a.ctx)
	}
}

func (a *App) CloseWindow() {
	if a.ctx == nil {
		return
	}
	if a.quitting.Load() || a.tray == nil {
		runtime.Quit(a.ctx)
		return
	}
	runtime.WindowHide(a.ctx)
}

// SetCustomFrame persists whether BENCchat draws its own titlebar. It takes effect
// on the next launch (the frameless flag is read at window creation). Bound to JS.
func (a *App) SetCustomFrame(on bool) string {
	a.cfg.CustomFrame = on
	if err := config.Save(a.cfg); err != nil {
		return err.Error()
	}
	return ""
}

// showWindow restores and focuses the window (from a tray click), and clears the
// tray notification dot. Safe to call before the context is set — it no-ops
// until startup has run.
func (a *App) showWindow() {
	if a.ctx == nil {
		return
	}
	a.tray.SetBadge(false)
	runtime.WindowUnminimise(a.ctx)
	runtime.WindowShow(a.ctx)
}

// quitApp performs a real exit (tray "Quit"). It sets the quitting flag so
// beforeClose lets the close through instead of hiding to the tray.
func (a *App) quitApp() {
	if a.ctx == nil {
		return
	}
	a.quitting.Store(true)
	runtime.Quit(a.ctx)
}

// beforeClose intercepts the window close button. Unless we're really quitting
// (tray "Quit"), it hides the window to the tray and vetoes the close, keeping
// BENCchat signed on in the background. Returning true prevents the close.
func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	if a.quitting.Load() || a.tray == nil {
		return false
	}
	runtime.WindowHide(ctx)
	return true
}

// stdruntimeGOOSIsDarwin reports whether we're on macOS. Wrapped so window.go
// doesn't need its own import alias for the std runtime package (app.go already
// aliases it).
func stdruntimeGOOSIsDarwin() bool { return stdruntime.GOOS == "darwin" }
