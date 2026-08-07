//! One Link's own window. No browser, no tabs, no address bar, no second brand in the taskbar.
//!
//! WHAT THIS REPLACES. The launcher opened the UI with `msedge.exe --app=<url>`, which produces a
//! chromeless window and is genuinely close to a native app — but it is Edge. It needs Edge
//! installed, it inherits Edge's update cadence and policies, it shows Edge in the process list,
//! and the window belongs to a browser that One Link does not control. This is our window.
//!
//! THREE PROPERTIES THIS HOST HAS THAT THE APP-MODE PATH DID NOT:
//!
//! 1. THE URL NEVER TOUCHES A COMMAND LINE. It arrives on **stdin**. A command line is readable by
//!    any process running as the same user with no elevation — measured on Windows via
//!    `Win32_Process` — and the URL carries the launch credential. stdin is visible to nobody.
//!
//! 2. NAVIGATION IS FENCED TO LOOPBACK. A webview that follows any link is a browser with our
//!    origin's storage attached: a peer-supplied link would render inside the trusted window. Every
//!    navigation away from `http://127.0.0.1:<port>` is REFUSED here and handed to the system
//!    browser instead, where it belongs.
//!
//! 3. THE DAEMON OUTLIVES THE WINDOW, which is a product requirement, not an accident: One Link's
//!    peers stay reachable after you close the UI. This process spawns nothing and owns nothing —
//!    when the window closes, this exits and the daemon is untouched.
//!
//! IT FAILS LOUDLY. If the webview runtime is missing or the URL is not loopback, this exits
//! non-zero with a reason on stderr so the launcher can fall back to the browser path *visibly*.
//! A shell that silently did nothing would leave a user staring at a dock icon that never opens.

mod certified;

use std::io::{self, BufRead, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

/// The SHA-256 of the interface this binary is willing to render, fixed at build time by `build.rs`.
///
/// Not passed in at runtime ON PURPOSE: an attacker who can edit `index.html` can edit whatever
/// told the shell what to expect, and a check whose expectation travels with the thing it checks
/// confirms tampering rather than catching it.
const UI_SHA256: &str = env!("OL_UI_SHA256");

/// Signers whose certified surfaces this build will render. Must match
/// `one_link/certified_surface.py::TRUSTED_VIEW_SIGNERS` — a divergence does not fail loudly, it
/// refuses every honest artifact, so `test_certified_surface.py` pins them together.
const TRUSTED_SIGNERS: &[&str] =
    &["30f8f6f794ab0059926bb61fa8e63a19dfea84505b5ccee5c30f87df36fd39a1"];

use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use wry::WebViewBuilder;
#[cfg(target_os = "windows")]
use wry::WebViewBuilderExtWindows;

/// PRIVACY ARGUMENTS FOR THE EMBEDDED RUNTIME (Windows/WebView2).
///
/// A stock WebView2 is a Chromium: left alone it does background networking, fetches component
/// updates, uploads crash dumps, and talks to optimisation/telemetry endpoints. None of that is
/// One Link's business, and a peer-to-peer tool whose whole promise is "your conversation does not
/// go through anybody" should not open a window that quietly does.
///
/// THIS SET IS DELIBERATELY SMALL, and that is a lesson from this repository rather than caution
/// for its own sake. `app.py` records that a previous over-hardened flag set for the Edge app-mode
/// launcher "could make double-clicks look dead on some Windows machines" — a hardening list nobody
/// verified, that broke launching. Every flag here is either a documented no-network switch or a
/// first-run suppression, and the window is verified to still open with them applied.
///
/// Note what is NOT here: no `--disable-features` grab-bag, no GPU/sandbox flags. Disabling the
/// renderer sandbox to "harden" a browser is the exact inversion people ship by accident.
#[cfg(target_os = "windows")]
const PRIVACY_ARGS: &str = concat!(
    "--disable-background-networking ",
    "--disable-component-update ",
    "--disable-breakpad ",
    "--disable-domain-reliability ",
    "--disable-sync ",
    "--no-first-run ",
    "--no-default-browser-check ",
    "--no-pings",
);

/// Printed on stdout once the window and webview exist. The launcher waits for this rather than
/// assuming success, because "the process started" and "a window opened" are different facts.
const READY: &str = "OL_SHELL_READY";

fn fail(reason: &str) -> ! {
    eprintln!("OL_SHELL_FAILED {reason}");
    std::process::exit(2)
}

/// Is `uri` inside `origin`? A PREFIX TEST IS NOT ENOUGH, and this is the bug I wrote first.
///
/// `"http://127.0.0.1:7117@evil.example/"` starts with `"http://127.0.0.1:7117"` — the loopback
/// address becomes **userinfo** and the real host is `evil.example`. A naive `starts_with` fence
/// therefore renders an attacker's page inside the window that holds our origin's storage. The
/// same shape admits `http://127.0.0.1:71170/` by digit extension.
///
/// So the origin must be followed by a genuine boundary: end of string, or one of `/ ? #`. Nothing
/// else may extend it.
fn same_origin(uri: &str, origin: &str) -> bool {
    match uri.strip_prefix(origin) {
        None => false,
        // -1 stands for end-of-string, exactly as the certified table encodes it.
        Some(rest) => admits_boundary(rest.chars().next().map(|c| c as i64).unwrap_or(-1)),
    }
}

/// THE DECISION, isolated so it can be checked against a THEOREM rather than against my judgement.
///
/// This predicate is `admits` in `idem/scripts/emit_certified_views.py`, discharged over EVERY
/// integer at scope `exact`:
///
///   only-a-real-boundary-may-extend-the-origin
///   userinfo-can-never-extend-the-origin
///   a-digit-can-never-extend-the-port
///   a-hostname-character-can-never-extend-the-origin
///   the-four-real-boundaries-ARE-admitted
///
/// `certified_agrees_with_the_proven_fence` below replays the shipped table through this function
/// for all 257 points. Rust is the plumbing; the security decision is the theorem.
pub fn admits_boundary(c: i64) -> bool {
    c == -1 || c == 47 || c == 63 || c == 35
}

/// The origin the window is allowed to be. Anything else is somebody else's page.
fn loopback_origin(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let host_port = rest.split('/').next()?;
    let (host, port) = host_port.rsplit_once(':')?;
    if host != "127.0.0.1" {
        return None;
    }
    // A port that is not a number would make the origin test compare garbage and pass everything.
    port.parse::<u16>().ok()?;
    Some(format!("http://{host}:{port}"))
}

fn main() {
    // THE URL ARRIVES ON STDIN, one line, and is never echoed. Reading it here rather than from
    // `std::env::args()` is the whole reason this is not three lines shorter.
    let mut url = String::new();
    if io::stdin().lock().read_line(&mut url).is_err() {
        fail("could not read the URL from stdin");
    }
    let url = url.trim().to_string();
    if url.is_empty() {
        fail("no URL on stdin");
    }

    // LINE 2: where the install lives, so the shell can verify what it is about to render. Not a
    // secret, but it arrives beside the URL rather than in argv so there is exactly one input
    // channel to reason about.
    let mut root = String::new();
    let _ = io::stdin().lock().read_line(&mut root);
    let root = root.trim().to_string();

    let origin = match loopback_origin(&url) {
        Some(o) => o,
        // Refusing a non-loopback URL is not defensive programming for its own sake: this process
        // is handed a URL by a parent, and a parent that has been tampered with should not be able
        // to point our trusted window at an arbitrary origin.
        None => fail("the URL is not http://127.0.0.1:<port> — refusing to host a foreign origin"),
    };

    // ---- THE PRECONDITIONS FOR OPENING A WINDOW AT ALL ----------------------------------
    //
    // Applications ship signed binaries; the OS checks them, and then the app draws whatever it
    // likes. Here the thing that owns the pixels refuses to open when what it would render does not
    // verify. The guarantee is the window's precondition, not a claim in a settings page.
    if !root.is_empty() {
        if let Err(why) = verify_interface(Path::new(&root)) {
            fail(&why);
        }
    } else {
        // An empty root is the launcher declining to say where it lives. Refusing outright would
        // make the shell unusable for anyone embedding it; saying so loudly is the honest middle,
        // and the Python side always sends it.
        eprintln!("OL_SHELL_UNVERIFIED no install root given; UI and surfaces were NOT verified");
    }

    let event_loop = EventLoop::new();
    let window = match WindowBuilder::new()
        .with_title("One Link")
        .with_inner_size(LogicalSize::new(1100.0, 760.0))
        .with_min_inner_size(LogicalSize::new(420.0, 480.0))
        .build(&event_loop)
    {
        Ok(w) => w,
        Err(e) => fail(&format!("could not create a window: {e}")),
    };

    let nav_origin = origin.clone();
    let mut builder = WebViewBuilder::new()
        .with_url(&url)
        // NO DEVTOOLS IN A SHIPPED WINDOW. Explicit rather than relying on the default: this window
        // holds an authenticated session, and an inspector is a console into it.
        .with_devtools(false)
        // THE FENCE. Returning false cancels the navigation inside our window. Anything that is
        // not our own origin is opened in the user's browser, which is where a stranger's link
        // should land — with none of our storage, and in a window that is visibly not the app.
        .with_navigation_handler(move |uri: String| {
            if same_origin(&uri, &nav_origin) {
                return true;
            }
            let _ = open_externally(&uri);
            false
        })
        // A new-window request (target=_blank) must not spawn a second chromeless window that
        // looks like the app but is pointed anywhere at all.
        .with_new_window_req_handler(move |uri: String, _features| {
            let _ = open_externally(&uri);
            wry::NewWindowResponse::Deny
        });

    #[cfg(target_os = "windows")]
    {
        builder = builder
            .with_additional_browser_args(PRIVACY_ARGS)
            // A browser extension in this window would be a third party inside an authenticated
            // session. There is no legitimate extension for a window that renders exactly one
            // local origin.
            .with_browser_extensions_enabled(false);
    }

    let _webview = match builder.build(&window) {
        Ok(w) => w,
        // The most common real cause on Windows is a missing WebView2 runtime. Naming it means the
        // launcher's fallback message can tell a user something they can act on.
        Err(e) => fail(&format!(
            "could not create the webview ({e}) — on Windows this usually means the WebView2 \
             runtime is not installed"
        )),
    };

    println!("{READY}");
    let _ = io::stdout().flush();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            // Closing the window ends THIS process and nothing else. The daemon was never a child
            // of ours; One Link's peers stay reachable with the UI closed, which is the behaviour
            // the launcher has always had and the reason this shell owns no lifecycle.
            *control_flow = ControlFlow::Exit;
        }
    });
}

/// Refuse to render an interface that is not the one this binary was built against, or a
/// certified surface that does not verify.
///
/// Returns `Err(reason)` and the caller exits non-zero, so the launcher falls back to the browser
/// path VISIBLY. A shell that opened anyway would be a security theatre generator.
fn verify_interface(root: &Path) -> Result<(), String> {
    let index = root.join("web").join("index.html");
    let bytes = std::fs::read(&index)
        .map_err(|e| format!("cannot read the interface at {} ({e})", index.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != UI_SHA256 {
        return Err(format!(
            "INTERFACE MODIFIED: {} hashes to {} but this shell was built to render {}. Something              changed the interface after it shipped; refusing to draw it.",
            index.display(),
            &got[..16],
            &UI_SHA256[..16.min(UI_SHA256.len())]
        ));
    }

    // The certified surfaces, verified by a SECOND implementation -- see certified.rs for why that
    // is the point rather than duplication.
    let dir = root.join("data").join("certified");
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read {} ({e})", path.display()))?;
            let doc: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("{} is not JSON ({e})", path.display()))?;
            let verdict = certified::verify(&doc, TRUSTED_SIGNERS);
            if !verdict.ok {
                return Err(format!(
                    "CERTIFIED SURFACE REFUSED ({}): {}",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
                    verdict.reason
                ));
            }
        }
    }
    Ok(())
}

/// Hand a foreign URL to the system browser. Best effort: failing to open someone else's link must
/// never take the window down.
fn open_externally(uri: &str) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        // `explorer.exe <uri>` is ShellExecute without a shell interpreter in the path.
        std::process::Command::new("explorer.exe")
            .arg(uri)
            .spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(uri).spawn()?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(uri).spawn()?;
    }
    Ok(())
}

#[cfg(test)]
// Test names shout on purpose: a failure line reading `a_non_ascii_artifact_is_REFUSED...`
// says what broke without opening the file. Readability beats the naming lint here.
#[allow(non_snake_case)]
mod tests {
    use super::{loopback_origin, same_origin};

    #[test]
    fn accepts_loopback_with_a_port() {
        assert_eq!(
            loopback_origin("http://127.0.0.1:7117/?t=abc").as_deref(),
            Some("http://127.0.0.1:7117")
        );
    }

    #[test]
    fn refuses_a_foreign_host() {
        // The attack this closes: a tampered parent points the trusted window somewhere else.
        assert!(loopback_origin("http://evil.example/?t=abc").is_none());
        assert!(loopback_origin("https://127.0.0.1:7117/").is_none());
        assert!(loopback_origin("http://127.0.0.1.evil.example:7117/").is_none());
    }

    #[test]
    fn refuses_a_hostless_or_portless_url() {
        assert!(loopback_origin("http://127.0.0.1/").is_none());
        assert!(loopback_origin("about:blank").is_none());
        assert!(loopback_origin("").is_none());
    }

    #[test]
    fn refuses_a_non_numeric_port() {
        // A port that does not parse would make the origin prefix test compare garbage, and a
        // prefix test that compares garbage passes things it should not.
        assert!(loopback_origin("http://127.0.0.1:notaport/").is_none());
    }

    #[test]
    fn userinfo_cannot_smuggle_a_foreign_host_past_the_fence() {
        // THE BUG THIS FILE SHIPPED FOR ABOUT TEN MINUTES. `http://127.0.0.1:7117@evil.example/`
        // starts with the loopback origin, because everything before the `@` is USERINFO and the
        // real host is `evil.example`. A prefix test renders that page inside the trusted window.
        let origin = loopback_origin("http://127.0.0.1:7117/").unwrap();
        assert!(
            "http://127.0.0.1:7117@evil.example/".starts_with(&origin),
            "if this is false the attack changed shape and the test below proves nothing"
        );
        assert!(!same_origin("http://127.0.0.1:7117@evil.example/", &origin));
        assert!(!same_origin("http://127.0.0.1:7117.evil.example/", &origin));
    }

    /// THE CROSS-IMPLEMENTATION CHECK. The shipped table is the materialisation of a predicate
    /// proven over every integer; this replays every one of its 257 points through the Rust and
    /// requires agreement. A disagreement means the plumbing drifted from the theorem it is
    /// supposed to implement — which is precisely how a fence rots while its proof stays green.
    #[test]
    fn the_rust_fence_agrees_with_the_PROVEN_table_at_every_point() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../src/one_link/data/certified/origin_fence.json"
        );
        let text = std::fs::read_to_string(path)
            .expect("the certified origin fence must ship beside the shell");
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        let rows = doc["rows"].as_array().expect("rows");
        assert_eq!(
            rows.len(),
            257,
            "the fence table is not the shipped 257 points"
        );

        let mut admitted = 0;
        for row in rows {
            let c = row["in"]["c"].as_i64().expect("axis c");
            let proven = row["out"].as_i64().expect("out") == 1;
            assert_eq!(
                super::admits_boundary(c),
                proven,
                "the Rust fence disagrees with the proven table at c={c}"
            );
            if proven {
                admitted += 1;
            }
        }
        // NON-VACUITY: a table that admitted nothing would make the agreement above trivial, and
        // the window would never open its own page.
        assert_eq!(
            admitted, 4,
            "exactly the four boundary characters should be admitted"
        );
    }

    #[test]
    fn a_digit_cannot_extend_the_port() {
        let origin = loopback_origin("http://127.0.0.1:7117/").unwrap();
        assert!(!same_origin("http://127.0.0.1:71170/x", &origin));
    }

    #[test]
    fn the_real_origin_is_still_admitted() {
        // NEGATIVE CONTROL. Every assertion above is satisfied by a fence that refuses
        // everything — which would be secure and would never open the app.
        let origin = loopback_origin("http://127.0.0.1:7117/").unwrap();
        for ok in [
            "http://127.0.0.1:7117",
            "http://127.0.0.1:7117/",
            "http://127.0.0.1:7117/?t=abc",
            "http://127.0.0.1:7117/peer.html#frag",
        ] {
            assert!(
                same_origin(ok, &origin),
                "the fence refuses our own page: {ok}"
            );
        }
    }
}
