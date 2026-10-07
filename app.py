"""Launch the local SecureLink graphical application."""
import argparse
from securelink.gui import run

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SecureLink graphical application')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--state', default='runtime/gui')
    parser.add_argument('--ready-file', help='Local automation only; contains a private application token')
    args = parser.parse_args()
    try:
        run(args.port, args.state, not args.no_browser, args.ready_file)
    except Exception as exc:
        if not args.no_browser:
            import tkinter
            from tkinter import messagebox
            root = tkinter.Tk()
            root.withdraw()
            messagebox.showerror('SecureLink could not start', str(exc))
            root.destroy()
        else:
            raise
