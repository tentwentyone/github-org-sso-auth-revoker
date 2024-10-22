# Revoke inactive GitHub Organization credentials

This GitHub Action revokes unused GitHub Personal Access Tokens (PATs) and SSH keys from an organization. It helps maintain security by removing credentials that have not been used for a specified number of days.

## Usage

```yaml
- name: Revoke Inactive Credentials
        uses: tentwentyone/github-org-sso-auth-revoker@v1
        with:
          days: ${{github.event.inputs.days || 45}}
          dry-run: ${{github.event.inputs.dry-run || true}}
          whitelist: ${{github.event.inputs.whitelist || secrets.GH_CRED_REVOKER_WHITELIST }}

          # GitHub App credentials
          gh_app_id: ${{ secrets.GH_CRED_REVOKER_APP_ID }}
          gh_pem_key: ${{ secrets.GH_CRED_REVOKER_PEM_KEY }}
          gh_install_id: ${{ secrets.GH_CRED_REVOKER_INSTALL_ID }}
```

### Example workflow

[Here](workflow.yml) you can find an example workflow that runs the action every week and revokes 45 days innactive credentials.

### How to list all / whitelist credentials linked to the organization

1. After setting up and running the action, you can run it manually with the `dry-run` input set to `true` and the `days` value set to `0`. This will list all the credentials associated with the organization.
2. Gather all the credential IDs that you want to preserve for whitelisting.
3. Set the `whitelist` input with a comma-separated list of the credential IDs (e.g., `123456, 123456789`).

## Prerequisites

### GitHub App

1. Create a GitHub App in the organization where you want to revoke credentials.
    - Repository permissions:
        - `metadata`: read-only
    - Organization permissions:
        - `administration`: read & write
        - `personal_access_token`: read & write
        - `members`: read-only
2. Generate a private key for the GitHub App.
3. Install the GitHub App in the organization.
4. Note the App ID, private key, and installation ID.
5. Encode the private key in base64 format.
6. Store the App ID, encoded private key, and installation ID as secrets in the repository (update secrets names as needed).

## Inputs

### Configurable via manual trigger

- `dry-run` (boolean): Indicates whether the action should perform a dry run. Default is `true` when triggered manually and `false` when triggered by a schedule.
- `days` (number): Number of days to check for inactive credentials. Default is `45`.
- `whitelist` (string): List of credential IDs to ignore (comma separated). If empty, the `GH_WHITELIST` environment variable will be used.

> the default values will be used when the trigger is a shedule

### Secrets

- `gh_app_id` (string): The GitHub App ID.
- `gh_pem_key` (string): The GitHub App private key (base64 encoded).
- `gh_install_id` (string): The GitHub App installation ID.

## Outputs

The results are added to the GitHub Actions summary.

### Example summary

![example action summary ](assets/images/summary_example.png)

## License

The scripts and documentation in this project are released under the [MIT License](LICENSE.md).

## Contributing

We welcome contributions! Please check our [guidelines](CONTRIBUTING.md) for details.

## Security Policy

Please see our [SECURITY.md](SECURITY.md) for details on our security policy and reporting security vulnerabilities.
