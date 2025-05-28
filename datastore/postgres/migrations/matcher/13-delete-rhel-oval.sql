-- The rhel-vex updater will now be responsible for RHEL advisories so we have
-- to delete the existing rhel vulnerabilities.
DELETE FROM update_operation
WHERE
  updater ~ 'RHEL[5-9]-*';

DELETE FROM vuln
where
  updater ~ 'RHEL[5-9]-*';
