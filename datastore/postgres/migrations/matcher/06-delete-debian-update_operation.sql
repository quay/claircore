DELETE FROM update_operation WHERE updater IN (
	'debian-bullseye-updater', 'debian-buster-updater',
	'debian-jessie-updater', 'debian-stretch-updater',
	'debian-wheezy-updater');
