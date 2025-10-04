 SET search_path TO 'public';


-- Tabela de usuários
CREATE TABLE users (
   id UUID PRIMARY KEY REFERENCES auth.users(id) on delete cascade,
   email VARCHAR(255) NOT NULL UNIQUE,
   full_name VARCHAR(255) NOT NULL,
   avatar_url TEXT,
   role user_role NOT NULL DEFAULT 'user',
   plan user_plan NOT NULL DEFAULT 'free',
   created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
   updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
