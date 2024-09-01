```markdown
# IAM3 Monorepo

This monorepo contains the complete implementation of a decentralized identity system, including authentication services, DID resolution, credential issuance, and a frontend application.

## Project Structure

```shell
iam3-monorepo/
├── services/
│   ├── iam3/           # Main IAM3 service
│   ├── resolver/       # DID Resolver service
│   └── issuer/         # Credential Issuer service
├── shared/             # Shared Go packages
│   └── models/
├── frontend/           # Next.js frontend application
├── scripts/            # Build and deployment scripts
└── docker-compose.yml  # Docker Compose configuration
```

## System Architecture

- IAM3 system. Here's a breakdown of the components:

1. Client Browser and Frontend App: The user interface layer.
2. API Gateway: Handles incoming requests and routes them to appropriate services.
3. IAM3 Service: Manages authentication and token issuance.
4. Resolver Service: Handles DID resolution.
5. Issuer Service: Issues verifiable credentials.
6. Shared Components: Common code and models used across services.
7. External Services: Iden3 Network, EVM Wallet, and Social Auth providers.


```
+---------------------+        +---------------------+
|                     |        |                     |
|   Client Browser    |        |    Frontend App     |
|                     |        |     (Next.js)       |
+----------+----------+        +---------+-----------+
           |                             |
           |  HTTP/HTTPS                 |
           |                             |
+----------v-----------------------------v-----------+
|                                                    |
|                   API Gateway                      |
|                                                    |
+----+----------------------+----------------------+-+
     |                      |                      |
     |                      |                      |
+----v----+            +----v----+            +----v----+
|         |            |         |            |         |
|  IAM3   |            |Resolver |            | Issuer  |
| Service |            | Service |            | Service |
|         |            |         |            |         |
+----+----+            +----+----+            +----+----+
     |                      |                      |
     |                      |                      |
+----v----------------------v----------------------v----+
|                                                      |
|                Shared Components                     |
|           (Models, Utilities, Interfaces)            |
|                                                      |
+------------------------------------------------------+
     |                      |                      |
     |                      |                      |
+----v----+            +----v----+            +----v----+
|         |            |         |            |         |
| Iden3   |            |  EVM    |            |  Social |
| Network |            | Wallet  |            |  Auth   |
|         |            |         |            |         |
+---------+            +---------+            +---------+
```

## Services

1. **IAM3 Service**: Handles authentication and token issuance.
   - Supports Iden3, EVM wallet, X (Twitter), and Discord authentication methods.
   - Implements OIDC-compliant flows.

2. **Resolver Service**: Resolves Decentralized Identifiers (DIDs).
   - Supports multiple DID methods.

3. **Issuer Service**: Issues verifiable credentials.

4. **Frontend**: Next.js application for user interaction.

## Prerequisites

- Go 1.17 or later
- Node.js 14 or later
- Docker and Docker Compose

## Getting Started

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/iam3-monorepo.git
   cd iam3-monorepo
   ```

2. Build and start all services:
   ```
   docker-compose up --build
   ```

3. Access the frontend at `http://localhost:3000`

## Development

### Backend Services

Each service in the `services/` directory can be developed independently:

```
cd services/iam3
go run cmd/server/main.go
```

### Frontend

To develop the frontend:

```
cd frontend
npm install
npm run dev
```

## Testing

Run tests for all services:

```
./scripts/test.sh
```

Or test individual services:

```
cd services/iam3
go test ./...
```

For frontend tests:

```
cd frontend
npm test
```

## Deployment

The project is configured for deployment using Docker. Use the provided `docker-compose.yml` for orchestration.

For production deployment, consider using Kubernetes or a similar container orchestration system.

## Configuration

Each service has its own configuration file. Update these files in the respective service directories as needed.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
```
