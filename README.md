# Cloud Access Security Broker (CASB) for SaaS Monitoring

A comprehensive Cloud Access Security Broker solution for monitoring and securing SaaS applications including Microsoft 365, Google Workspace, and Salesforce.

## Features

- **Real-time Monitoring**: Continuous monitoring of SaaS application activities
- **Anomaly Detection**: ML-based detection of unusual user behavior
- **Data Loss Prevention (DLP)**: Prevent sensitive data exfiltration
- **Policy Enforcement**: Customizable security policies and compliance rules
- **Multi-Platform Support**: Microsoft 365, Google Workspace, Salesforce integration
- **Dashboard & Reporting**: Interactive dashboard for security insights
- **Alerting System**: Real-time alerts via Slack and email
- **Audit Trail**: Comprehensive logging and audit capabilities

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SaaS Apps     │    │   CASB Core     │    │   Dashboard     │
│                 │    │                 │    │                 │
│ • Microsoft 365 │◄──►│ • Auth & AuthZ  │◄──►│ • Analytics     │
│ • Google Workspace│   │ • Monitoring    │    │ • Reports       │
│ • Salesforce    │    │ • DLP Engine    │    │ • Alerts        │
└─────────────────┘    │ • Policy Mgmt   │    └─────────────────┘
                       └─────────────────┘
                                │
                       ┌─────────────────┐
                       │   Data Store    │
                       │                 │
                       │ • PostgreSQL    │
                       │ • Redis Cache   │
                       └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- PostgreSQL and Redis (if not using Docker)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd "Set up cloud access security broker for SaaS monitoring"
```

2. Copy environment configuration:
```bash
cp .env.example .env
```

3. Update `.env` with your API keys and configuration

4. Start with Docker Compose:
```bash
docker-compose up -d
```

### Access Points

- **API Server**: http://localhost:8000
- **Dashboard**: http://localhost:8050
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090

## Configuration

### SaaS Application Setup

#### Microsoft 365
1. Register an application in Azure AD
2. Add API permissions for Microsoft Graph
3. Configure client ID, secret, and tenant ID

#### Google Workspace
1. Create a project in Google Cloud Console
2. Enable Admin SDK API
3. Create OAuth 2.0 credentials
4. Configure domain-wide delegation

#### Salesforce
1. Create a connected app in Salesforce
2. Enable OAuth 2.0
3. Configure consumer key and secret

### Security Policies

Configure policies in `config/policies.yaml`:

```yaml
policies:
  - name: "Block Large Downloads"
    type: "data_transfer"
    condition: "download_size > 100MB"
    action: "block"
  
  - name: "Alert on Suspicious Login"
    type: "authentication"
    condition: "new_location OR unusual_time"
    action: "alert"
```

## API Documentation

Once running, visit http://localhost:8000/docs for interactive API documentation.

## Monitoring & Metrics

- **Prometheus metrics**: http://localhost:8001/metrics
- **Grafana dashboards**: Pre-configured security dashboards
- **Log aggregation**: Structured logging with correlation IDs

## Development

### Local Development Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up database:
```bash
alembic upgrade head
```

3. Run the API server:
```bash
uvicorn app.main:app --reload
```

4. Run the dashboard:
```bash
python -m app.dashboard.main
```

### Running Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
black app/
flake8 app/
mypy app/
```

## Security Considerations

- All credentials are encrypted at rest
- API communication uses HTTPS/TLS
- Role-based access control (RBAC)
- Audit logging for all administrative actions
- Regular security updates and vulnerability scanning

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue in the repository.
