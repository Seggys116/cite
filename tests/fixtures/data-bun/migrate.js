// Build step of the data fixture: creates the table with the owner login the build link provides. Without the link
// (the first deploy of a site that has no database yet) it does nothing, so the build still succeeds.
const url = process.env.MIGRATION_DATABASE_URL;
if (!url) {
  console.log("migrate: MIGRATION_DATABASE_URL is not set, skipping");
  process.exit(0);
}
const sql = new Bun.SQL(url, { max: 1, connectionTimeout: 20 });
await sql`create table if not exists notes (
  id serial primary key,
  body text not null,
  created_at timestamptz not null default now()
)`;
await sql.close();
console.log("migrate: notes table ready");
