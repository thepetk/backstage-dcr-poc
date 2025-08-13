# Backstage DCR PoC

This repo tries to experiemnt with the suggested dynamic client registration feature implementation for Backstage. PR can be found here: https://github.com/backstage/backstage/pull/30606

## Background

Dynamic Client registration is essential for MCP authentication.

## Usage

This project requires some steps to be taken prior running the script.

- First we need to run the [backstage branch](https://github.com/backstage/backstage/tree/blam/oidc-auth/3) related to the implementation PR:

```bash
# clone the repo locally
git clone https://github.com/backstage/backstage.git
cd backstage
git checkout blam/oidc-auth/3
```

- Then you need to run the backend app. First you need to remove [this line](https://github.com/backstage/backstage/blob/blam/oidc-auth/3/packages/backend/src/index.ts#L36):

```ts
backend.add(import("@backstage/plugin-app-backend"));
```

- Finally inside the `backstage/packages/backend` you need to run:

```bash
yarn install
yarn start
```

- Now you have started the backstage API so you are able to interact locally with the backstage backend. All it remains is to run the script.

```bash
pip install .
python3 run main.py
```
