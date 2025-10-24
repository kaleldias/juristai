-- Atualiza campo finished_at da tabela contract_analyses
CREATE OR REPLACE FUNCTION fn_ca_set_finished_at()
RETURNS TRIGGER
AS $$
BEGIN
  IF NEW.STATUS IN ('SUCCEEDED','FAILED') AND NEW.finished_at IS NULL THEN
    NEW.finished_at := NOW();
  END IF;
  RETURN NEW;
$$ LANGUAGE plpgsql;