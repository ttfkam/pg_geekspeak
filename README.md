# pg_geekspeak
The GeekSpeak podcast database schema

## Install
On a Debian or Ubuntu system, run the following:

```bash
  $ sudo apt-get update
```

If not already installed, install PostgreSQL and required modules

```bash
  $ sudo apt-get install postgresql-10 postgresql-10-python3-multicorn
```
Install development tools

```bash
  $ sudo apt-get install postgresql-server-dev-10
```
Download pg_geekspeak and run the following inside the project directory

```bash
  $ sudo make install
  $ make installcheck
```

Verify all tests pass and use the geekspeak extension in the database. From within PostgreSQL

```sql
  CREATE EXTENSION geekspeak CASCADE;
```

This will install all required extensions (btree_gist, isn, multicorn, pgcrypto, and plpgsql) as well. You can of course install each dependency manually if you prefer.
