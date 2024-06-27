-- The rhel-vex updater will now be responsible for RHCC advisories so we have
-- to delete the existing RHCC vulnerabilities.
DELETE FROM update_operation WHERE updater = 'rhel-container-updater';
DELETE FROM vuln where updater = 'rhel-container-updater';
