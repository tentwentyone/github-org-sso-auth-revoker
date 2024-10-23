import datetime
import logging
import os
import jwt
import requests
import argparse
import base64
from rich import print
from rich.logging import RichHandler
from rich.table import Table
from rich import box
from rich.console import Console
import sys


class GHWrapper:
    # This class is a wrapper around the GitHub API to list and delete Personal Access Tokens (PATs) and SAML SSO authorizations (PATs fine-grained and SSH keys)
    # The class uses the GitHub App authentication method to get a token with organization permissions to list and delete PATs and SAML SSO authorizations

    # Github token permissions required:
    #   Organization:
    #       Administration: Read & write
    #       members: read
    #       personal access tokens: read & write
    #   Repository: (this allows us to install the app on a specific repository)
    #       Metadata: read

    # To get the token, you need to set the following environment variables:
    #   GH_APP_ID: the GitHub App ID
    #   GH_PEM_KEY_PATH or GH_PEM_KEY: the path to the private key or the private key itself encoded in base64
    #   GH_INSTALL_ID: the GitHub App installation ID
    #   GH_ORG: the organization name

    # Another Environment variable available is:
    #   GH_WHITELIST: a comma separated list of PAT IDs to exclude from deletion (optional)

    def __init__(self, app_id, pem_key_path, install_id, org, pem_key=None, whitelist=[]):
        self.app_id = app_id
        self.install_id = install_id
        self.pem_key_path = pem_key_path
        self.pem_key = pem_key
        self.token = self.get_gh_token()
        self.org = org
        self.whitelist = whitelist

    def get_gh_token(self):
        """
        Get a GitHub API token using the GitHub App authentication

        Returns:
            dict: with the following
                - token: the GitHub API token
                - expires_at: the expiration date of the token
                - permissions: the permissions of the token
                - repository_selection: the repository selection of the token
        """

        creds = {
            "app_id": self.app_id,
            "pem_key_path": self.pem_key_path,
            "install_id": self.install_id,
            "pem_key": self.pem_key,
        }

        # check if pem_key is defined and decode it from base64
        if creds["pem_key"] is not None:
            creds["pem_key"] = base64.b64decode(creds["pem_key"]).decode("utf-8")

        # if pem_key is not defined, check if pem_key_path is defined and read the content of the file
        elif creds["pem_key"] is None and creds["pem_key_path"] is not None:
            # check if pem_key path exists and read the content
            if os.path.exists(creds["pem_key_path"]):
                with open(creds["pem_key_path"], "r") as f:
                    creds["pem_key"] = f.read().strip()

        if len(creds["app_id"]) == 0 or len(creds["pem_key"]) == 0 or len(creds["install_id"]) == 0:
            raise Exception("GH_APP_CREDS is not set correctly")

        now = int(datetime.datetime.now().timestamp())
        payload = {
            "iat": now - 60,
            "exp": now + 60 * 8,  # expire after 8 minutes
            "iss": creds["app_id"],
        }
        encoded = jwt.encode(payload=payload, key=creds["pem_key"], algorithm="RS256")

        url = f'https://api.github.com/app/installations/{creds["install_id"]}/access_tokens'
        headers = {
            "Authorization": f"Bearer {encoded}",
        }
        response = requests.post(url, headers=headers)

        if response.status_code != 201:
            logging.error(f"[bold red]Failed to get app token from GitHub API: {response.text}", extra={"markup": True})

        # example of response content {'token': 'ghs_XXXXXXXXXXXXXXXX', 'expires_at': '2024-04-15
        if response.status_code == 201:
            logging.debug("[bold green]Successfully got GitHub API token", extra={"markup": True})
            return response.json()["token"]

    def list_pat(
        self,
        per_page=100,
        sort="created_at",
        direction="desc",
        owner=None,
        repository=None,
        permission=None,
        last_used_before=None,
        last_used_after=None,
    ):
        """
        List fine-grained personal access tokens with access to organization resources

        Returns:
            list: a list of personal access tokens without any credentials present in the whitelist
        Reference:
            https://docs.github.com/en/rest/orgs/personal-access-tokens?apiVersion=2022-11-28#list-fine-grained-personal-access-tokens-with-access-to-organization-resources

        Caveats:
            Since the API is paginated, the function will run until the last page returns an empty list
            When a token expires, the token_expires_at field is not present in the response

        """

        pats = []

        for page in range(1, 100):
            url = f"https://api.github.com/orgs/{self.org}/personal-access-tokens"
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
            }
            params = {
                "per_page": per_page,
                "sort": sort,
                "direction": direction,
                "page": page,
                "owner": owner,
                "repository": repository,
                "permission": permission,
                "last_used_before": last_used_before,
                "last_used_after": last_used_after,
            }
            response = requests.get(url, headers=headers, params=params)

            if response.status_code != 200:
                logging.error(
                    f"[bold red]Failed to list personal access tokens from GitHub API: {response.text}",
                    extra={"markup": True},
                )

            json_response = response.json()

            if len(json_response) == 0:
                break
                # last page reached

            elif len(json_response) < per_page:  ##
                pats.extend(json_response)
                break
                # last page reached
            else:
                pats.extend(json_response)

        # Filter out the tokens in the whitelist
        filtered_pats = []

        for pat in pats:
            if pat["id"] in self.whitelist:
                logging.debug(
                    f"[bold orange3]PAT ID {pat['id']} is in the whitelist, skipping it", extra={"markup": True}
                )
                continue
            else:
                filtered_pats.append(pat)

        filtered_pats_without_expired = []

        for pat in filtered_pats:
            if pat.get("token_expired", None) is True:
                logging.debug(f"[bold orange3]PAT ID {pat['id']} is expired, skipping it", extra={"markup": True})
                continue
            else:
                filtered_pats_without_expired.append(pat)

        return filtered_pats_without_expired

    def list_unused_pat(self, days=1):
        """
        List fine-grained personal access tokens with access to organization resources that have not been used in the last X days, this wont include tokens that have never been used

        Returns:
            list: a list of personal access tokens
        """

        return self.list_pat(last_used_before=(datetime.datetime.now() - datetime.timedelta(days=days + 1)).isoformat())

    def list_expired_pat(self):
        """
        List fine-grained personal access tokens with access to organization resources that have expired

        Returns:
            list: a list of personal access tokens
        """

        logging.info("Listing expired personal access tokens")

        pats = self.list_pat()

        return [pat for pat in pats if pat["token_expired"]]

    def list_pats_unused_for(self, days=1):
        """
        List fine-grained personal access tokens with access to organization resources that have not been used in the last X days

        When a pat has never been used, the creation date is used as the last_used_at date.

        For example, if you are looking for tokens that have not been used in the last 30 days, and a token was created 31 days ago and never used, it will be included in the list.


        Args:
            days (int): number of days to consider a token as unused

        Returns:
            list: a list of personal access tokens
        """

        # logging.info(f"Listing personal access tokens unused for +{days} days")

        pats = self.list_pat()  # get all pats

        # check if the token has been used in the last X days
        unused_pats = []

        for pat in pats:
            last_used_at_str = (
                pat["token_last_used_at"] if pat["token_last_used_at"] is not None else pat["access_granted_at"]
            )
            if pat["token_last_used_at"] is not None:
                last_used_at = datetime.datetime.strptime(last_used_at_str, "%Y-%m-%dT%H:%M:%SZ")
                if last_used_at < (datetime.datetime.now() - datetime.timedelta(days=days)):
                    unused_pats.append(pat)

        return unused_pats

    def delete_pats(self, pat_ids: list):
        """
        Delete a personal access token

        Args:
            pat_ids (list): a list of personal access token IDs

        Returns:
            bool: True if the token was deleted successfully, False otherwise
        """

        # https://docs.github.com/en/rest/orgs/personal-access-tokens?apiVersion=2022-11-28#update-the-access-to-organization-resources-via-fine-grained-personal-access-tokens

        assert isinstance(pat_ids, list), "pat_ids should be a list of integers"

        # filter out the tokens in the whitelist
        for pat_id in pat_ids:
            if pat_id in self.whitelist:
                logging.info(
                    f"[bold orange3]PAT ID {pat_id} is in the whitelist, skipping deletion", extra={"markup": True}
                )
                pat_ids.remove(pat_id)

        if args.dry_run:
            logging.info(f"[bold orange3]DRY-RUN - Deleting PATs {pat_ids}", extra={"markup": True})
            return True

        if len(pat_ids) == 0:
            logging.info("[bold orange3]No PATs (fine-grained) to delete", extra={"markup": True})
            return True

        url = f"https://api.github.com/orgs/{self.org}/personal-access-tokens"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        data = {"action": "revoke", "pat_ids": pat_ids}

        logging.info(f"[bold orange3]Deleting PATs {pat_ids}", extra={"markup": True})

        response = requests.post(url, headers=headers, json=data)

        if response.status_code != 202:
            logging.error(
                f"[bold red]Failed to delete personal access tokens from GitHub API: {response.text}",
                extra={"markup": True},
            )
            return False
        else:
            logging.info(
                f"[bold green]Successfully deleted personal access tokens {pat_ids} from GitHub API",
                extra={"markup": True},
            )
            return True

    def list_saml_sso_authorizations(self, days=0, per_page=100, page=1):
        """
        List credential authorizations for an organization that uses SAML SSO. The list includes the credential ID, the user who authorized the credential, and the date and time the credential was authorized.

        When a credential has never been used, the creation date is used instead of the last accessed date.


        Args:
            days (int): number of days to consider a credential as unused (default 0) - 0 means all credentials will be returned
            per_page (int): number of items per page (default 100)
            page (int): page number (default 1)


        Returns:
            list: a list of credential authorizations

        Reference:
            # https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs?apiVersion=2022-11-28#list-saml-sso-authorizations-for-an-organization

        Example response:
        [
            {
                "login":"hubot",
                "credential_id":30233948,
                "credential_type":"personal access token",
                "credential_authorized_at":"2022-04-05T11:55:08Z",
                "credential_accessed_at":"2024-10-17T21:55:07Z",
                "authorized_credential_id":692744952,
                "token_last_eight":"yXXXXXXo",
                "scopes":[
                    "delete:packages",
                    "repo",
                    "workflow",
                    "write:packages"
                ],
                "authorized_credential_note":"name of pat here",
                "authorized_credential_expires_at":"None",
                "application_name":"None",
                "application_client_id":"None"
            },
            {
                "login":"user12",
                "credential_id":32202196,
                "credential_type":"SSH key",
                "credential_authorized_at":"2022-04-21T10:56:33Z",
                "credential_accessed_at":"2024-10-17T17:12:53Z",
                "authorized_credential_id":65568893,
                "fingerprint":"SHA256:o5eXXXXFigXyCIYAXXXAYA1f123455XXXWXXXwqs",
                "authorized_credential_title":"work ssh  key"
            },
            {
                'login': 'someuser',
                'credential_id': 358124641,
                'credential_type': 'OAuth app token',
                'credential_authorized_at': '2022-06-06T12:48:02Z',
                'credential_accessed_at': '2024-10-14T07:58:15Z',
                'authorized_credential_id': 887341235,
                'token_last_eight': 'BXXXXXa',
                'scopes': [
                    'read:user',
                    'repo',
                    'user:email',
                    'workflow'
                    ],
                'authorized_credential_note': None,
                'authorized_credential_expires_at': None,
                'application_name': 'Visual Studio Code',
                'application_client_id': '01ab221c9400c4e429b23'
            },
            {
                "login":"anotheruser",
                "credential_id":39411394,
                "credential_type":"GitHub app token",
                "credential_authorized_at":"2022-07-15T14:38:15Z",
                "credential_accessed_at":"2024-10-22T10:11:10Z",
                "authorized_credential_id":918339000,
                "token_last_eight":"uXXXXXX7",
                "scopes":[],
                "authorized_credential_note":"None",
                "authorized_credential_expires_at":"None",
                "application_name":"Microsoft Teams for GitHub",
                "application_client_id":"Iv1.2b3f60f5d77cb30d"
            }

        ]

        """

        last_used_before = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        credentials = []

        url = f"https://api.github.com/orgs/{self.org}/credential-authorizations"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        for page in range(1, 100):
            params = {"per_page": 100, "page": page}

            response = requests.get(url, headers=headers, params=params)

            if response.status_code != 200:
                logging.error(
                    f"[bold red]Failed to list SAML SSO authorizations from GitHub API: {response.text}",
                    extra={"markup": True},
                )

            json_response = response.json()

            if len(json_response) == 0:
                break
                # last page reached
            elif len(json_response) < 100:
                credentials.extend(json_response)
                break
                # last page reached
            else:
                credentials.extend(json_response)

        # since this API does not return a boolean for expired, we need to calculate it

        for credential in credentials:
            # check if the expiration date is in the future (not expired) or if it is in the past (expired)
            expired = True
            expires_at = credential.get("authorized_credential_expires_at", None)
            if expires_at is not None:  # if the expiration date is present
                expires_at_dtime = datetime.datetime.strptime(
                    expires_at, "%Y-%m-%dT%H:%M:%S.%fZ"
                )  # convert to datetime
                if expires_at_dtime > datetime.datetime.now():  # if the expiration date is in the future
                    expired = False
            else:
                expired = False
            credential["expired"] = expired

        # Filter out the credentials in the whitelist
        filtered_credentials = []
        for credential in credentials:
            if credential["credential_id"] in self.whitelist:
                logging.debug(
                    f"[bold orange3]Credential ID {credential['credential_id']} is in the whitelist, skipping it",
                    extra={"markup": True},
                )
                continue
            else:
                filtered_credentials.append(credential)

        # filter expired credentials

        filtered_credentials_without_expired = []

        for credential in filtered_credentials:
            if credential["expired"] is True:
                logging.debug(
                    f"[bold orange3]Credential ID {credential['credential_id']} is expired, skipping it",
                    extra={"markup": True},
                )
                continue
            else:
                filtered_credentials_without_expired.append(credential)

        # Filter credentials
        if days > 0:
            # Filter  for credentials that have not been accessed in the last <days>
            # include credentials that have never been accessed

            filtered_credentials_days = []

            for credential in filtered_credentials_without_expired:
                # last_accessed_at = credential.get("credential_accessed_at", None)
                last_accessed_at = (
                    credential.get("credential_accessed_at", None)
                    if credential.get("credential_accessed_at", None) is not None
                    else credential.get("credential_authorized_at", None)
                )

                if last_accessed_at is None:  # if the credential has never been accessed
                    continue  # skip this credential
                if last_accessed_at <= last_used_before:
                    filtered_credentials_days.append(credential)

            return filtered_credentials_days
        else:
            return filtered_credentials

    def revoke_saml_sso_authorization(self, credential_id):
        """
        Remove a credential authorization for an organization that uses SAML SSO.

        Returns:
            bool: True if the credential was revoked successfully, False otherwise

        Reference:
            # https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs?apiVersion=2022-11-28#remove-a-saml-sso-authorization-for-an-organization

        """

        if credential_id in self.whitelist:
            logging.info(
                f"[bold orange3]Credential ID {credential_id} is in the whitelist, skipping revocation",
                extra={"markup": True},
            )
            return True

        if args.dry_run:
            logging.info(
                f"[bold orange3]DRY-RUN - Skip Revocation of SAML SSO authorization {credential_id}",
                extra={"markup": True},
            )
            return True

        url = f"https://api.github.com/orgs/{self.org}/credential-authorizations/{credential_id}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        response = requests.delete(url, headers=headers)

        if response.status_code == 403:
            logging.error(
                f"[bold red]Missing required permissions to revoke SAML SSO authorization from GitHub API: {response.text}",
                extra={"markup": True},
            )
            return False

        if response.status_code == 404:
            logging.error(f"[bold red]Credential ID {credential_id} not found", extra={"markup": True})
            return False
        elif response.status_code != 204:
            logging.error(
                f"[bold red]Failed to revoke SAML SSO authorization from GitHub API: {response.text}",
                extra={"markup": True},
            )
            return False

        logging.debug(
            f"[bold green]Successfully revoked SAML SSO authorization {credential_id} from GitHub API",
            extra={"markup": True},
        )
        return True

    def revoke_saml_sso_authorizations(self, credential_ids: list):
        """
        Remove a list of credential authorizations for an organization that uses SAML SSO.

        Args:
            credential_ids (list): a list of credential IDs

        Returns:
            bool: True if all credentials were revoked successfully, False otherwise

        """

        assert isinstance(credential_ids, list), "credential_ids should be a list of integers"

        all_revoke_success = True

        for credential_id in credential_ids:
            ret = self.revoke_saml_sso_authorization(credential_id)
            if not ret:
                all_revoke_success = False

        return all_revoke_success


def pretty_print_pat(pat):
    logging.info(
        f"Owner: [bold medium_spring_green]{pat['owner']['login']}[/] Token ID: [bold medium_spring_green]{pat['id']}[/] Access Granted At: [bold medium_spring_green]{pat['access_granted_at']}[/]  Last Used: [bold medium_spring_green]{pat['token_last_used_at']}[/] Expires At: [bold medium_spring_green]{pat.get('token_expires_at','No expiration date')}[/]  Expired: [bold medium_spring_green]{pat['token_expired']}[/]",
        extra={"markup": True},
    )


def pretty_print_pats(pats):
    if args.out_format == "txt":
        for pat in pats:
            pretty_print_pat(pat)
    elif args.out_format == "table":
        console.print("## Personal Access Tokens (PATs) fine-grained")
        if len(pats) == 0:
            console.print("No credentials found")
        else:
            table = Table(title="", safe_box=True, box=box.MARKDOWN)
            table.add_column("Owner", style="medium_spring_green")
            table.add_column("Token ID", style="medium_spring_green")
            table.add_column("Access Granted At", style="medium_spring_green")
            table.add_column("Last Used", style="medium_spring_green")
            table.add_column("Expires At", style="medium_spring_green")
            table.add_column("Expired", style="medium_spring_green")
            for pat in pats:
                table.add_row(
                    str(pat["owner"]["login"]),
                    str(pat["id"]),
                    str(pat["access_granted_at"]),
                    str(pat["token_last_used_at"]),
                    str(pat.get("token_expires_at", "No expiration date")),
                    str(pat["token_expired"]),
                    style="bright_red" if pat["token_expired"] else "medium_spring_green",
                )

            console.print(table)


def pretty_print_credential(credential):
    logging.info(
        f"Owner: [bold medium_spring_green]{credential['login']}[/] Name: [bold medium_spring_green]{credential.get('authorized_credential_note',credential.get('authorized_credential_title',''))}[/] Type: [bold medium_spring_green]{credential['credential_type']}[/] ID: [bold medium_spring_green]{credential['credential_id']}[/]  Access Granted At: [bold medium_spring_green]{credential['credential_authorized_at']}[/] Last Used: [bold medium_spring_green]{credential['credential_accessed_at']}[/]  Expires At: [bold medium_spring_green]{credential.get('authorized_credential_expires_at', 'No expiration date')}[/] Expired: [bold medium_spring_green]{credential['expired']}[/]",
        extra={"markup": True},
    )


def pretty_print_credentials(credentials):
    if args.out_format == "txt":
        for credential in credentials:
            pretty_print_credential(credential)
    elif args.out_format == "table":
        console.print("## SAML SSO Authorizations PATs (classic) and SSH Keys")

        if len(credentials) == 0:
            console.print("No credentials found")
        else:
            table = Table(title="", safe_box=True, box=box.MARKDOWN, title_justify="left")
            table.add_column("Owner", style="medium_spring_green")
            table.add_column("Name", style="medium_spring_green")
            table.add_column("Type", style="medium_spring_green")
            table.add_column("ID", style="medium_spring_green")
            table.add_column("Access Granted At", style="medium_spring_green")
            table.add_column("Last Used", style="medium_spring_green")
            table.add_column("Expires At", style="medium_spring_green")
            table.add_column("Expired", style="medium_spring_green")

            name_field_mapping = {
                "personal access token": "authorized_credential_note",
                "SSH key": "authorized_credential_title",
                "OAuth app token": "application_name",
                "GitHub app token": "application_name",
            }

            for credential in credentials:
                table.add_row(
                    str(credential["login"]),
                    str(credential.get(name_field_mapping[credential["credential_type"]], "")),
                    str(credential["credential_type"]),
                    str(credential["credential_id"]),
                    str(credential["credential_authorized_at"]),
                    str(credential["credential_accessed_at"]),
                    str(credential.get("authorized_credential_expires_at", "No expiration date")),
                    str(credential["expired"]),
                    style="bright_red" if credential["expired"] else "medium_spring_green",
                )

            console.print(table)


def add_workflow_job_summary(t_pats, t_creds, days, dry_run):
    """Adds a job summary.
    Args:
        t_pats (markdown table): a markdown table with the PATs
        t_creds (markdown table): a markdown table with the credentials
        days (int): number of days to consider a PAT/SSH as unused
        dry_run (bool): True if it is a dry run
    """

    # Capture the tables into a variable
    with console.capture() as capture:
        console.print(
            "# Credentials inactive for ",
            days,
            " days" if days > 0 else "# All credentials associated with the organization",
        )
        pretty_print_pats(pats)
        console.print("\n" * 2)
        pretty_print_credentials(credentials)
        if dry_run:
            console.print("> :warning: DRY-RUN - No deletion was performed")

    # Save the table as a string in a variable
    text = capture.get()

    # Add the tables to the workflow job summary

    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
        print(text, file=f)


def parse_command_line_args(args_0=sys.argv[1:]):
    arg_parser = argparse.ArgumentParser(
        description="Find and delete unused GitHub Personal Access Tokens (PATs) associated with an organization"
    )

    arg_parser.add_argument("-d", "--days", type=int, help="Number of days to consider a PAT/SSH as unused", default=0)
    arg_parser.add_argument(
        "--dry-run",
        choices=["True", "true", "False", "false"],
        default="True",
        help="Instead of deleting, just print what would be deleted",
    )
    arg_parser.add_argument("-o", "--out-format", type=str, default="table", help="Output format: table or txt")
    arg_parser.add_argument(
        "-w",
        "--whitelist",
        type=str,
        default=[],
        help="Comma separated list of PAT IDs to exclude from deletion (optional) override the GH_WHITELIST env variable",
    )
    arg_parser.add_argument("--no-color", action="store_true", help="Disable color output")

    args = arg_parser.parse_args(args_0)
    assert args.dry_run in ["True", "true", "False", "false"], "dry-run should be either True or False"
    args.dry_run = True if args.dry_run == "True" or args.dry_run == "true" else False

    if len(args.whitelist) != 0:
        args.whitelist = [int(pat_id) for pat_id in args.whitelist.split(",")]
    elif os.getenv("GH_WHITELIST") is not None and os.getenv("GH_WHITELIST") != "":
        args.whitelist = [int(pat_id) for pat_id in os.getenv("GH_WHITELIST").split(",")]

    if args.whitelist == "":  # if the whitelist is an empty string (github actions default input)
        args.whitelist = []

    return args


if __name__ == "__main__":
    args = parse_command_line_args()

    FORMAT = "%(message)s"
    console = Console(force_terminal=True, color_system="auto" if args.no_color is False else None)

    logging.basicConfig(
        level=logging.INFO if os.getenv("RUNNER_DEBUG") != "1" else logging.DEBUG,
        format=FORMAT,
        datefmt="[%X]",
        handlers=[RichHandler(console=console, markup=True)],
    )

    logging.debug(f"Arguments: {args}")
    logging.debug(f"Environment variables: GH_WHITELIST: {os.getenv('GH_WHITELIST')}")

    if args.days == 0 and args.dry_run is False:
        logging.warning(
            "[bold red]WARNING: You are about to delete all credentials associated with the organization, to prevent this, dry_run will be overridden to True",
            extra={"markup": True},
        )
        args.dry_run = True

    gh = GHWrapper(
        app_id=os.getenv("GH_APP_ID"),
        pem_key_path=os.getenv("GH_PEM_KEY_PATH"),
        pem_key=os.getenv("GH_PEM_KEY"),
        install_id=os.getenv("GH_INSTALL_ID"),
        org=os.getenv("GH_ORG"),
        whitelist=args.whitelist,
    )

    logging.info(
        "Listing PATs (fine-grained), PATs (classic) and SSH Keys " + f" not used in the last {args.days} days"
        if args.days > 0
        else ""
    )

    pats = gh.list_pats_unused_for(days=args.days)

    credentials = gh.list_saml_sso_authorizations(days=args.days)

    if "GITHUB_STEP_SUMMARY" in os.environ:
        add_workflow_job_summary(t_pats=pats, t_creds=credentials, days=args.days, dry_run=args.dry_run)

    pretty_print_pats(pats)
    console.print("\n" * 2)
    pretty_print_credentials(credentials)

    if args.dry_run:
        logging.info("[bold orange3]DRY-RUN - No deletion will be performed", extra={"markup": True})

    else:
        gh.delete_pats(pat_ids=[pat["id"] for pat in pats if not pat["token_expired"]])
        gh.revoke_saml_sso_authorizations(
            credential_ids=[credential["credential_id"] for credential in credentials if not credential["expired"]]
        )
