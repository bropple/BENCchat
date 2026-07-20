package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/benco-holdings/benchat/internal/tray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

//go:embed all:frontend/dist
var assets embed.FS

// Build identity, stamped at link time with -ldflags "-X main.version=... -X
// main.commit=...". The defaults are what an un-stamped local build reports, and
// they are deliberately obvious: a client that cannot talk to the server because
// it predates a wire change looks identical to a healthy one until you can read
// its build off the sign-on screen, which is exactly the failure this exists to
// make visible.
var (
	version = "dev"
	commit  = "unknown"
)

// Application/tray icons, rendered from the R. Triy mark
// (assets/brand/benco-roster-triy.svg).
// appIconPNG doubles as the Linux window icon; the tray uses PNG on Linux/macOS
// and ICO on Windows.
//
//go:embed assets/appicon.png
var appIconPNG []byte

//go:embed assets/tray.png
var trayIconPNG []byte

//go:embed assets/tray.ico
var trayIconICO []byte

//go:embed assets/tray-badge.png
var trayBadgePNG []byte

//go:embed assets/tray-badge.ico
var trayBadgeICO []byte

func main() {
	// Refuse to start a second copy. Two instances share one config file, one
	// history, one trust record and one device key — they overwrite each
	// other's device list and each looks to the server like the other has gone
	// rogue. Checked before any window appears, so the duplicate exits rather
	// than flashing up and dying.
	if !claimSingleInstance() {
		fmt.Fprintln(os.Stderr, "BENCchat is already running.")
		// Windows launches from Explorer with no console, so stderr alone would
		// be invisible; the dialog is the only way the user finds out there.
		notifyAlreadyRunning()
		return
	}

	app := NewApp()
	app.trayIcons = tray.Icons{
		NormalPNG: trayIconPNG,
		NormalICO: trayIconICO,
		BadgePNG:  trayBadgePNG,
		BadgeICO:  trayBadgeICO,
	}
	app.desktopIcon = appIconPNG

	// The window chrome follows the BENCO palette: a green-tinted near-black
	// base rather than pure black, per the design style guide.
	err := wails.Run(&options.App{
		Title:  "BENCchat",
		Width:  920,
		Height: 640,
		// Opt-in custom titlebar: when on, the window is frameless and the
		// frontend draws BENCchat's own titlebar (see the "Custom window frame"
		// setting). Off by default so the desktop environment decorates normally.
		Frameless:        app.cfg.CustomFrame,
		MinWidth:         720,
		MinHeight:        480,
		BackgroundColour: &options.RGBA{R: 0x0c, G: 0x14, B: 0x08, A: 1},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:     app.startup,
		OnShutdown:    app.shutdown,
		OnBeforeClose: app.beforeClose,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
		// The Linux window/taskbar icon (Windows takes its icon from the compiled
		// build/windows/icon.ico that `wails build` embeds from build/appicon.png).
		// ProgramName sets the GTK app-id / WM_CLASS to "benchat", which is what
		// KDE (X11 and Wayland) matches against the installed desktop entry (see
		// installDesktopEntry) to resolve the titlebar/taskbar icon.
		Linux: &linux.Options{
			Icon:        appIconPNG,
			ProgramName: "benchat",
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
