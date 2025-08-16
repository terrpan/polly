# GitHub Enterprise Server Setup

This document describes how to configure Polly to work with GitHub Enterprise Server instances.

## Configuration

### Environment Variables

For GitHub Enterprise Server, you'll need to configure the base URL and optionally the upload URL:

```bash
# Required GitHub App configuration
export POLLY_GITHUB_APP_ID=123456
export POLLY_GITHUB_INSTALLATION_ID=789012
export POLLY_GITHUB_PRIVATE_KEY_PATH="/path/to/private-key.pem"

# GitHub Enterprise Server URLs
export POLLY_GITHUB_BASE_URL="https://github.enterprise.com/api/v3"
export POLLY_GITHUB_UPLOAD_URL="https://github.enterprise.com/api/uploads"  # Optional
```

### Configuration File

Alternatively, you can use a YAML configuration file:

```yaml
github:
  app_id: 123456
  installation_id: 789012
  private_key_path: "/path/to/private-key.pem"
  base_url: "https://github.enterprise.com/api/v3"
  upload_url: "https://github.enterprise.com/api/uploads"  # Optional, defaults to base_url
```

## Configuration Options

### `base_url` (string, optional)
- **Default**: `"https://api.github.com"` (GitHub.com API)
- **Purpose**: API base URL for your GitHub Enterprise Server instance
- **Format**: Must be a valid URL (e.g., `https://github.enterprise.com/api/v3`)
- **Required for**: GitHub Enterprise Server instances

### `upload_url` (string, optional)
- **Default**: `"https://uploads.github.com"` (GitHub.com uploads)
- **Purpose**: Upload URL for artifacts and attachments
- **Format**: Must be a valid URL (e.g., `https://github.enterprise.com/api/uploads`)
- **Required for**: GitHub Enterprise Server instances with separate upload endpoints

## Examples

### Standard GitHub Enterprise Server
Most GitHub Enterprise Server instances use the standard path structure:

```yaml
github:
  app_id: 123456
  installation_id: 789012
  private_key_path: "/path/to/private-key.pem"
  base_url: "https://your-github-enterprise.com/api/v3"
```

### GitHub.com (Default)
For GitHub.com, no additional configuration is needed as the defaults are already set:

```yaml
github:
  app_id: 123456
  installation_id: 789012
  private_key_path: "/path/to/private-key.pem"
  # base_url defaults to "https://api.github.com"
  # upload_url defaults to "https://uploads.github.com"
```

### Personal Access Token with Enterprise
The enterprise URL configuration also works with Personal Access Token authentication:

```bash
export POLLY_GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
export POLLY_GITHUB_BASE_URL="https://github.enterprise.com/api/v3"
```

## Validation

Polly validates the URL format during startup. Invalid URLs will result in clear error messages:

- `invalid GITHUB_BASE_URL: <error details>`
- `invalid GITHUB_UPLOAD_URL: <error details>`

## Backward Compatibility

Existing configurations without `base_url` will continue to work unchanged and will connect to GitHub.com by default.

## Testing Your Configuration

To verify your GitHub Enterprise Server configuration is working:

1. Start Polly with your enterprise configuration
2. Check the health endpoint: `GET /health`
3. The GitHub client should successfully authenticate with your enterprise instance

## Troubleshooting

### Common Issues

1. **Invalid URL format**: Ensure your URLs start with `https://` and are properly formatted
2. **Network connectivity**: Verify that Polly can reach your GitHub Enterprise Server instance
3. **GitHub App permissions**: Ensure your GitHub App has the necessary permissions on your enterprise instance
4. **API version**: GitHub Enterprise Server may have different API versions - adjust the URL path accordingly

### Error Messages

- `invalid GITHUB_BASE_URL`: The base URL format is invalid
- `invalid GITHUB_UPLOAD_URL`: The upload URL format is invalid
- `failed to configure GitHub Enterprise URLs`: The go-github library rejected the provided URLs

For additional help, check the application logs for detailed error messages.