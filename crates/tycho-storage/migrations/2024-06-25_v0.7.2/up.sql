CREATE EXTENSION pg_cron;

SELECT cron.schedule('@daily', $$CALL partman.run_maintenance_proc()$$);