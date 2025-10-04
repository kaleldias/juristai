SET search_path TO 'public';

-- Cria um tipo enumerado para roles
CREATE TYPE user_role AS ENUM ('admin', 'user');
-- Cria um tipo enumerado para planos
CREATE TYPE user_plan AS ENUM ('free', 'pro');