DROP TRIGGER IF EXISTS trg_ca_set_finished_at ON contract_analyses;

-- Chama a função que atualiza o campo "finished_at" da tabela "contract_analyses"
CREATE TRIGGER trg_ca_set_finished_at
BEFORE INSERT OR UPDATE
ON contract_analyses 
FOR EACH ROW
EXECUTE FUNCTION fn_ca_set_finished_at;