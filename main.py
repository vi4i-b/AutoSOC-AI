"""AutoSOC entry point: login window first, then the dashboard."""

from autosoc.env import load_env_file
from autosoc.logging_setup import configure_logging


def main():
    configure_logging()
    load_env_file()

    # Imported lazily so logging/env are configured before any UI module runs.
    from autosoc.ui.dashboard import AutoSOCApp
    from autosoc.ui.login import launch

    def on_login_success(user):
        app = AutoSOCApp(current_user=user)
        app.title(f"AutoSOC: Cyber Shield v3.0  |  {user['username']} ({user['role']})")
        app.mainloop()

    launch(on_login_success)


if __name__ == "__main__":
    main()
