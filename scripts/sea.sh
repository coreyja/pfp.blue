#!/usr/bin/env bash

sea-orm-cli generate entity --expanded-format --ignore-tables oauth_tokens_temp -o server/src/orm
