SET search_path TO 'public';

UPDATE users 
SET role = 'admin' 
WHERE id = '73c4654a-2637-45ac-9ee2-64c5c617a388';

SELECT * FROM users;