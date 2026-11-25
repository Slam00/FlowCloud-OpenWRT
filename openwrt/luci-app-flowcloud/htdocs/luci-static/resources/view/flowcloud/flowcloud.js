'use strict';
'require view';
'require dom';
'require form';
'require fs';
'require poll';
'require ui';
'require uci';
'require tools.widgets as widgets';

var DAEMON = '/usr/bin/flowcloudd';

var STATE_LABELS = {
	starting: _('Запуск'),
	registering: _('Регистрация WARP'),
	selecting: _('Подбор сервера'),
	up: _('Работает'),
	down: _('Недоступен'),
	disabled: _('Выключен'),
	error: _('Ошибка')
};

var STATE_COLORS = {
	up: '#2e9a5b',
	selecting: '#c98a14',
	registering: '#c98a14',
	starting: '#c98a14',
	down: '#c94141',
	error: '#c94141',
	disabled: '#888'
};

var DOMAIN_RE = /^(\*\.|\.)?([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.?$/i;
var IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}(\/([0-9]|[12]\d|3[0-2]))?$/;

function tokens(text) {
	var result = [];
	(text || '').split('\n').forEach(function(line) {
		line = line.replace(/\/\/.*$/, '').replace(/#.*$/, '');
		line.split(/[\s,;]+/).forEach(function(token) {
			if (token.length)
				result.push(token);
		});
	});
	return result;
}

function validateEntries(check, kind) {
	return function(sectionId, value) {
		var bad = tokens(value).filter(function(token) { return !check(token); });
		if (!bad.length)
			return true;
		return _('Неверные %s: %s').format(kind, bad.slice(0, 5).join(', ') + (bad.length > 5 ? ' …' : ''));
	};
}

function validateURL(sectionId, value) {
	if (!value || /^https?:\/\/[^\s]+$/.test(value))
		return true;
	return _('Нужна ссылка http:// или https://');
}

function badge(text, color) {
	return E('span', {
		'style': 'display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:90%;background:' + color
	}, text);
}

function pingCell(ms) {
	if (ms == null || ms < 0)
		return E('span', { 'style': 'color:#888' }, '—');
	var color = ms < 120 ? '#2e9a5b' : (ms < 300 ? '#c98a14' : '#c94141');
	return E('span', { 'style': 'color:' + color + ';font-weight:bold' }, ms + ' ' + _('мс'));
}

function formatTime(unix) {
	if (!unix)
		return '—';
	return new Date(unix * 1000).toLocaleString();
}

function renderStatus(status) {
	if (!status || !status.running) {
		var reason = _('Служба не запущена. Включите FlowCloud в настройках и сохраните.');
		if (status && status.error && status.error != 'FlowCloud is disabled in settings')
			reason = status.error;
		return E('div', { 'class': 'alert-message warning' }, reason);
	}

	var nodes = [];
	(status.warnings || []).forEach(function(warning) {
		nodes.push(E('div', { 'class': 'alert-message warning' }, warning));
	});

	var tunnelRows = (status.tunnels || []).map(function(t) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, t.name)),
			E('td', { 'class': 'td' }, t.type == 'warp' ? 'WARP' : _('Интерфейс')),
			E('td', { 'class': 'td' }, badge(STATE_LABELS[t.state] || t.state, STATE_COLORS[t.state] || '#888')),
			E('td', { 'class': 'td' }, E('code', {}, t.endpoint || '—')),
			E('td', { 'class': 'td' }, pingCell(t.ping_ms)),
			E('td', { 'class': 'td' }, t.profile || ''),
			E('td', { 'class': 'td', 'style': 'color:#c94141' }, t.error || '')
		]);
	});
	nodes.push(E('h3', {}, _('Туннели')));
	nodes.push(E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Туннель')),
			E('th', { 'class': 'th' }, _('Тип')),
			E('th', { 'class': 'th' }, _('Состояние')),
			E('th', { 'class': 'th' }, _('Сервер / устройство')),
			E('th', { 'class': 'th' }, _('Пинг')),
			E('th', { 'class': 'th' }, _('Профиль')),
			E('th', { 'class': 'th' }, '')
		])
	].concat(tunnelRows)));

	var actionLabels = { tunnel: '→ ', direct: _('напрямую'), block: _('блокировка') };
	var sectionRows = (status.sections || []).map(function(s) {
		var target = s.action == 'tunnel' ? '→ ' + s.tunnel : actionLabels[s.action];
		var notes = [];
		if (!s.enabled)
			notes.push(_('выключена'));
		if (s.missing && s.missing.length)
			notes.push(_('не загружено списков: %d').format(s.missing.length));
		if (s.invalid && s.invalid.length)
			notes.push(_('пропущено неверных записей: %d').format(s.invalid.length));
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, s.name)),
			E('td', { 'class': 'td' }, target),
			E('td', { 'class': 'td' }, String(s.domains)),
			E('td', { 'class': 'td' }, String(s.subnets)),
			E('td', { 'class': 'td', 'style': 'color:#c98a14' }, notes.join('; '))
		]);
	});
	nodes.push(E('h3', {}, _('Секции')));
	nodes.push(E('table', { 'class': 'table' }, [
		E('tr', { 'class': 'tr table-titles' }, [
			E('th', { 'class': 'th' }, _('Секция')),
			E('th', { 'class': 'th' }, _('Куда')),
			E('th', { 'class': 'th' }, _('Доменов')),
			E('th', { 'class': 'th' }, _('Подсетей')),
			E('th', { 'class': 'th' }, '')
		])
	].concat(sectionRows)));

	var dns = status.dns || {};
	nodes.push(E('p', {}, [
		E('strong', {}, _('DNS') + ' '), E('code', {}, dns.listen || ''), ': ',
		_('%d запросов, %d по спискам, %d адресов добавлено, %d ошибок').format(dns.queries || 0, dns.matched || 0, dns.learned || 0, dns.failures || 0),
		dns.dnsmasq_integration ? '' : E('em', {}, ' — ' + _('dnsmasq не перенаправлен, домены не отслеживаются'))
	]));
	nodes.push(E('p', {}, [ E('strong', {}, _('Списки обновлены: ')), formatTime(status.lists_updated) ]));
	(status.list_errors || []).forEach(function(error) {
		nodes.push(E('div', { 'style': 'color:#c94141;font-size:90%' }, error));
	});
	return E('div', {}, nodes);
}

return view.extend({
	load: function() {
		return Promise.all([
			fs.exec_direct(DAEMON, [ 'presets' ], 'json').catch(function() { return []; }),
			fs.exec_direct(DAEMON, [ 'status', '-json' ], 'json').catch(function() { return null; }),
			uci.load('flowcloud')
		]);
	},

	render: function(data) {
		var presets = data[0] || [];
		var initialStatus = data[1];
		var m, s, o;

		m = new form.Map('flowcloud', '', '');
		m.tabbed = true;

		/* Sections */
		s = m.section(form.TypedSection, 'section', _('Секции'),
			_('Каждая секция — набор доменов и подсетей и то, что с ними делать.'));
		s.addremove = true;
		s.anonymous = false;
		s.sortable = true;
		s.addbtntitle = _('Добавить секцию');

		o = s.option(form.Flag, 'enabled', _('Включена'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.ListValue, 'action', _('Действие'));
		o.value('tunnel', _('Через туннель'));
		o.value('direct', _('Напрямую (исключение)'));
		o.value('block', _('Блокировать'));
		o.default = 'tunnel';

		o = s.option(form.ListValue, 'tunnel', _('Туннель'));
		uci.sections('flowcloud', 'tunnel').forEach(function(tunnel) {
			var label = tunnel['.name'] + (tunnel.type == 'interface' ? ' (' + (tunnel.interface || '?') + ')' : ' (WARP)');
			o.value(tunnel['.name'], label);
		});
		o.depends('action', 'tunnel');
		o.rmempty = false;

		o = s.option(form.DynamicList, 'community_lists', _('Списки сообщества'),
			_('Готовые списки доменов и подсетей из <a href="%s" target="_blank">itdoginfo/allow-domains</a>, обновляются автоматически.').format('https://github.com/itdoginfo/allow-domains'));
		presets.forEach(function(preset) {
			o.value(preset.name, preset.label + (preset.subnets ? ' ' + _('(+подсети)') : ''));
		});

		o = s.option(form.TextValue, 'domains_text', _('Свои домены'),
			_('По одному на строку или через запятую. Поддомены включаются автоматически. Комментарии: // или #.'));
		o.rows = 8;
		o.wrap = 'off';
		o.validate = validateEntries(function(token) { return DOMAIN_RE.test(token); }, _('домены'));

		o = s.option(form.TextValue, 'subnets_text', _('Свои IP и подсети'),
			_('IPv4-адреса и подсети, например 149.154.160.0/20. Маршрутизируются сразу, без DNS.'));
		o.rows = 5;
		o.wrap = 'off';
		o.validate = validateEntries(function(token) { return IPV4_RE.test(token) || token.indexOf(':') >= 0; }, _('адреса'));

		o = s.option(form.DynamicList, 'remote_domain_lists', _('Ссылки на списки доменов'),
			_('Текстовые списки по ссылке: один домен на строку.'));
		o.validate = validateURL;

		o = s.option(form.DynamicList, 'remote_subnet_lists', _('Ссылки на списки подсетей'),
			_('Текстовые списки по ссылке: один адрес или подсеть на строку.'));
		o.validate = validateURL;

		/* Tunnels */
		s = m.section(form.TypedSection, 'tunnel', _('Туннели'),
			_('WARP-туннель регистрируется в Cloudflare сам, подбирает сервер и профиль маскировки AmneziaWG и меняет сервер, если тот перестал отвечать. Любой другой VPN-интерфейс роутера (AmneziaWG, WireGuard, OpenVPN) подключается как «Существующий интерфейс».'));
		s.addremove = true;
		s.anonymous = false;
		s.addbtntitle = _('Добавить туннель');

		o = s.option(form.Flag, 'enabled', _('Включён'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.ListValue, 'type', _('Тип'));
		o.value('warp', _('Cloudflare WARP (автоподбор сервера)'));
		o.value('interface', _('Существующий интерфейс'));
		o.default = 'warp';

		o = s.option(widgets.NetworkSelect, 'interface', _('Интерфейс'),
			_('Сетевой интерфейс OpenWrt, через который пойдёт трафик.'));
		o.nocreate = true;
		o.depends('type', 'interface');

		o = s.option(form.Value, 'device', _('Имя устройства'),
			_('Устройство AmneziaWG, которое создаст FlowCloud (до 15 символов).'));
		o.placeholder = 'fcwarp';
		o.datatype = 'and(maxlength(15),minlength(1))';
		o.depends('type', 'warp');

		o = s.option(form.Value, 'probe_parallel', _('Проверять одновременно'),
			_('Сколько серверов проверяется параллельно при подборе. На роутерах с 128 МБ памяти лучше 4–8.'));
		o.datatype = 'range(1,24)';
		o.placeholder = '8';
		o.depends('type', 'warp');

		o = s.option(form.Value, 'health_interval', _('Проверка каждые, с'),
			_('Как часто проверять, что туннель пропускает трафик.'));
		o.datatype = 'range(5,3600)';
		o.placeholder = '15';

		o = s.option(form.Flag, 'fail_closed', _('Не пускать мимо туннеля'),
			_('Если туннель недоступен, трафик его секций блокируется, а не идёт напрямую.'));
		o.default = '0';

		/* Settings */
		s = m.section(form.NamedSection, 'settings', 'settings', _('Настройки'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Включить FlowCloud'));
		o.rmempty = false;

		o = s.option(form.Flag, 'dnsmasq_integration', _('Перенаправить DNS роутера'),
			_('dnsmasq будет отправлять запросы в FlowCloud: так отслеживаются домены из секций. Предыдущие настройки DNS восстанавливаются при остановке. Не включайте одновременно с podkop.'));
		o.rmempty = false;

		o = s.option(form.DynamicList, 'dns_upstream', _('Вышестоящие DNS'),
			_('DoH (https://…), UDP (1.1.1.1 или udp://1.1.1.1:53) или TCP (tcp://…). Запросы к ним идут напрямую.'));
		o.value('https://1.1.1.1/dns-query', 'Cloudflare DoH');
		o.value('https://8.8.8.8/dns-query', 'Google DoH');
		o.value('https://9.9.9.9/dns-query', 'Quad9 DoH');
		o.value('1.1.1.1', 'Cloudflare UDP');
		o.value('8.8.8.8', 'Google UDP');

		o = s.option(form.Flag, 'strip_aaaa', _('Без IPv6 для доменов из секций'),
			_('Маршрутизация работает по IPv4; без AAAA-ответов устройства не обойдут туннель через IPv6.'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'update_interval', _('Обновлять списки'));
		o.value('1h', _('каждый час'));
		o.value('6h', _('каждые 6 часов'));
		o.value('12h', _('каждые 12 часов'));
		o.value('24h', _('раз в сутки'));
		o.value('72h', _('раз в 3 дня'));
		o.default = '24h';

		o = s.option(widgets.DeviceSelect, 'source_interfaces', _('Сети-источники'),
			_('Трафик с этих устройств маршрутизируется по секциям.'));
		o.multiple = true;
		o.noaliases = true;
		o.nobridges = false;

		o = s.option(form.Flag, 'route_router_traffic', _('Трафик самого роутера'),
			_('Маршрутизировать по секциям и соединения, которые открывает сам роутер.'));
		o.rmempty = false;

		o = s.option(form.Value, 'dns_listen', _('Адрес DNS FlowCloud'));
		o.datatype = 'ipaddrport(1)';
		o.placeholder = '127.0.0.53:53';

		var statusNode = E('div', { 'id': 'flowcloud-status' }, renderStatus(initialStatus));
		var buttons = E('div', { 'class': 'cbi-page-actions', 'style': 'text-align:left;padding-top:0' }, [
			E('button', {
				'class': 'cbi-button cbi-button-action',
				'click': ui.createHandlerFn(this, function() {
					return fs.exec(DAEMON, [ 'update-lists' ]).then(function() {
						ui.addNotification(null, E('p', _('Обновление списков запущено.')), 'info');
					});
				})
			}, _('Обновить списки')),
			' ',
			E('button', {
				'class': 'cbi-button cbi-button-neutral',
				'click': ui.createHandlerFn(this, function() {
					return fs.exec('/etc/init.d/flowcloud', [ 'restart' ]);
				})
			}, _('Перезапустить службу'))
		]);

		poll.add(function() {
			return fs.exec_direct(DAEMON, [ 'status', '-json' ], 'json').then(function(status) {
				var target = document.getElementById('flowcloud-status');
				if (target)
					dom.content(target, renderStatus(status));
			}).catch(function() {});
		}, 5);

		return m.render().then(function(mapNode) {
			return E('div', {}, [
				E('h2', {}, _('FlowCloud')),
				E('div', { 'class': 'cbi-map-descr' }, _('Направляет выбранные сайты и подсети через WARP и другие туннели. Домены отслеживаются через DNS роутера, подсети маршрутизируются сразу. Секции проверяются сверху вниз: при совпадении срабатывает первая.')),
				E('div', { 'class': 'cbi-section' }, [ statusNode, buttons ]),
				mapNode
			]);
		});
	}
});
