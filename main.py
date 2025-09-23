import classes.Auth as auth


if __name__ == "__main__":
    auth = auth.Auth()
    failed_logins = auth.get_failed_login_counts()
    print(failed_logins)