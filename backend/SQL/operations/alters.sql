SET search_path TO 'public';

/*
 Adiciona coluna 'active' para controle de conta, se false usuario cancelou sua conta
 Se true ainda esta com conta ativa.
*/
ALTER TABLE users ADD COLUMN active BOOLEAN DEFAULT true;




SELECT * FROM users;