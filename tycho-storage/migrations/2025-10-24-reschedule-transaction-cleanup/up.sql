-- Schedule the cleanup function to run daily at 12:00 PM
-- This is to ensure that the cleanup function runs during team work hours and allows for timely reactions
-- to any issues it may cause with indexer DB interactions.
SELECT cron.schedule('clean_transaction_table', '0 12 * * *', 'SELECT clean_transaction_table();');
