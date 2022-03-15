-- Delete all the alpine updaters that have fixed_in_version of 0.
DELETE FROM update_operation WHERE updater IN (
	'alpine-community-v3.13-updater', 'alpine-community-v3.14-updater',
	'alpine-community-v3.15-updater', 'alpine-main-v3.10-updater',
	'alpine-main-v3.11-updater', 'alpine-main-v3.12-updater'
	'alpine-main-v3.13-updater', 'alpine-main-v3.14-updater'
	'alpine-main-v3.15-updater', 'alpine-main-v3.8-updater');
