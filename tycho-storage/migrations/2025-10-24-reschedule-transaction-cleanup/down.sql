-- Schedule the cleanup function to run daily at 12:30 AM (after partition pruning at midnight)
SELECT cron.schedule('clean_transaction_table', '30 0 * * *', 'SELECT clean_transaction_table();');
