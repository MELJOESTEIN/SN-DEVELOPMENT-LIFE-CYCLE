# Branching Strategy

## Main Branches
- `main`: Production-ready code.
- `develop`: Ongoing development.

## Feature Branches
- `feature/planning`: Planning tasks.
- `feature/design`: Design and threat modeling.
- `feature/implementation`: Coding and integration.
- `feature/testing`: Security testing.
- `feature/deployment`: Deployment and maintenance.

## Support Branches
- `hotfix/`: Urgent fixes.
- `release/`: Release preparation.

## Access Rules
- Developers: Write access to feature branches and `develop`.
- Security Lead: Full access to all branches.
- QA Team: Read-only access to `main` and `develop`, write access to `feature/testing`.

