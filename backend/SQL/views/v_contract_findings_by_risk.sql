CREATE OR REPLACE VIEW v_contract_findings_by_risk 
WITH (security_invoker = true) AS
SELECT 
  analyses_id,
  risk,
  COUNT(*)::BIGINT AS total
FROM contract_findings
GROUP BY analyses_id, risk;

GRANT SELECT ON v_contract_findings_by_risk TO authenticated;
REVOKE ALL ON v_contract_findings_by_risk TO public;
