# pg_geekspeak
The GeekSpeak podcast database schema

## Install
On an Ubuntu system, run the following:

```bash
  $ sudo apt-get update
```

If not already installed, install PostgreSQL and required modules

```bash
  $ sudo apt-get install postgresql-9.6 postgresql-9.6-python3-multicorn postgresql-contrib-9.6
```
Install development tools

```bash
  $ sudo apt-get install postgresql-server-dev-9.6
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
