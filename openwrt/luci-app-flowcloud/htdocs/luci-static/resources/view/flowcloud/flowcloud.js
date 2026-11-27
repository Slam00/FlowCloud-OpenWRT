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
	idle: _('Не используется'),
	error: _('Ошибка')
};

var STATE_COLORS = {
	up: '#2e9a5b',
	selecting: '#c98a14',
	registering: '#c98a14',
	starting: '#c98a14',
	down: '#c94141',
	error: '#c94141',
	disabled: '#888',
	idle: '#888'
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

// Median ping and loss over the quality window (two minutes by default).
function qualityCell(t) {
	if (t.median_ms == null || t.median_ms < 0)
		return E('span', { 'style': 'color:#888' }, '—');
	var lossColor = t.loss_pct >= 30 ? '#c94141' : (t.loss_pct > 0 ? '#c98a14' : '#888');
	return E('span', {}, [
		_('медиана %d мс').format(t.median_ms), ', ',
		E('span', { 'style': 'color:' + lossColor }, _('потери %d%%').format(t.loss_pct || 0))
	]);
}

var COLO_NAMES = {
	DME: _('Москва'), LED: _('Санкт-Петербург'), ARN: _('Стокгольм'), HEL: _('Хельсинки'),
	WAW: _('Варшава'), FRA: _('Франкфурт'), AMS: _('Амстердам'), RIX: _('Рига'),
	TLL: _('Таллин'), VNO: _('Вильнюс'), KBP: _('Киев'), IST: _('Стамбул')
};

function coloName(colo) {
	return COLO_NAMES[colo] ? COLO_NAMES[colo] + ' (' + colo + ')' : colo;
}

// Test sites opened through the applied WARP tunnel.
function sitesCell(sites) {
	if (!sites || !sites.length)
		return '';
	return E('div', {}, sites.map(function(r) {
		var host = r.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
		return E('span', {
			'title': r.ok ? _('открывается, %d мс').format(r.ms) : (r.error || ''),
			'style': 'margin-right:8px;color:' + (r.ok ? '#2e9a5b' : '#c94141')
		}, (r.ok ? '✓ ' : '✗ ') + host);
	}));
}

var ZAPRET_STATES = {
	starting: [ _('Запуск'), '#c98a14' ],
	ok: [ _('Работает'), '#2e9a5b' ],
	failing: [ _('Не открывается'), '#c94141' ],
	searching: [ _('Подбор стратегии'), '#c98a14' ],
	error: [ _('Ошибка'), '#c94141' ],
	unavailable: [ _('Не установлен'), '#888' ]
};

function renderZapret(z) {
	var state = ZAPRET_STATES[z.state] || [ z.state, '#888' ];
	var rows = (z.results || []).map(function(r) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('code', {}, r.url)),
			E('td', { 'class': 'td' }, r.ok
				? E('span', { 'style': 'color:#2e9a5b' }, _('открывается, %d мс').format(r.ms))
				: E('span', { 'style': 'color:#c94141' }, r.error || _('не открывается')))
		]);
	});
	return E('div', {}, [
		E('h3', {}, _('zapret2')),
		E('p', {}, [
			badge(state[0], state[1]), ' ',
			z.label ? _('стратегия: %s').format(z.label) : '',
			z.auto ? E('em', {}, ' (' + _('автоподбор') + ')') : '',
			z.switches ? ' · ' + _('смен стратегии: %d').format(z.switches) : '',
			z.checked_at ? ' · ' + _('проверено %s').format(formatTime(z.checked_at)) : ''
		]),
		z.error ? E('div', { 'style': 'color:#c94141' }, z.error) : '',
		rows.length ? E('table', { 'class': 'table' }, rows) : ''
	]);
}

function formatTime(unix) {
	if (!unix)
		return '—';
	return new Date(unix * 1000).toLocaleString();
}

function notRunning(status) {
	if (status && status.running)
		return null;
	var reason = _('Служба не запущена. Включите FlowCloud в настройках и сохраните.');
	if (status && status.error && status.error != 'FlowCloud is disabled in settings')
		reason = status.error;
	return E('div', { 'class': 'alert-message warning' }, reason);
}

function openDiagnostics(ev) {
	if (ev)
		ev.preventDefault();
	var tab = document.querySelector('.cbi-tabmenu li[data-tab="diagnostics"] a');
	if (tab)
		tab.click();
}

function chip(title, children) {
	return E('a', {
		'href': '#',
		'click': openDiagnostics,
		'title': _('Подробнее на вкладке «Диагностика»'),
		'style': 'display:inline-flex;align-items:center;gap:6px;padding:4px 10px;margin:0 6px 6px 0;border:1px solid rgba(128,128,128,.35);border-radius:6px;text-decoration:none;color:inherit'
	}, [ E('strong', {}, title) ].concat(children));
}

// renderSummary is the short block on top of every tab: one chip per tunnel
// and one for zapret2; the details live on the Diagnostics tab.
function renderSummary(status) {
	var stopped = notRunning(status);
	if (stopped)
		return stopped;
	var nodes = [];
	(status.warnings || []).forEach(function(warning) {
		nodes.push(E('div', { 'class': 'alert-message warning' }, warning));
	});
	var chips = (status.tunnels || []).map(function(t) {
		return chip(t.name, [
			badge(STATE_LABELS[t.state] || t.state, STATE_COLORS[t.state] || '#888'),
			t.state == 'up' ? pingCell(t.ping_ms) : '',
			t.colo ? E('span', { 'style': 'color:#888', 'title': coloName(t.colo) }, t.colo) : '',
			t.error && t.state != 'up' ? E('span', { 'style': 'color:#c94141;font-size:90%' }, '!') : ''
		]);
	});
	var z = status.zapret;
	if (z && z.active) {
		var state = ZAPRET_STATES[z.state] || [ z.state, '#888' ];
		var results = z.results || [];
		var passed = results.filter(function(r) { return r.ok; }).length;
		chips.push(chip('zapret2', [
			badge(state[0], state[1]),
			results.length ? E('span', { 'style': 'color:' + (passed == results.length ? '#2e9a5b' : '#c94141') },
				_('%d из %d').format(passed, results.length)) : ''
		]));
	}
	nodes.push(E('div', {}, chips));
	return E('div', {}, nodes);
}

function renderStatus(status, warpSwitch) {
	var stopped = notRunning(status);
	if (stopped)
		return stopped;

	var nodes = [];

	var tunnelRows = (status.tunnels || []).map(function(t) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, t.name)),
			E('td', { 'class': 'td' }, t.type == 'warp' ? 'WARP' : (t.type == 'opera' ? 'Opera' : _('Интерфейс'))),
			E('td', { 'class': 'td' }, badge(STATE_LABELS[t.state] || t.state, STATE_COLORS[t.state] || '#888')),
			E('td', { 'class': 'td' }, [
				E('code', {}, t.endpoint || '—'),
				t.colo ? E('div', { 'style': 'font-size:90%;color:#888' }, _('выход: %s').format(coloName(t.colo))) : ''
			]),
			E('td', { 'class': 'td' }, pingCell(t.ping_ms)),
			E('td', { 'class': 'td' }, qualityCell(t)),
			E('td', { 'class': 'td' }, t.profile || ''),
			E('td', { 'class': 'td' }, [
				sitesCell(t.sites),
				t.reconnects ? E('div', {
					'style': 'color:#888;font-size:90%',
					'title': _('Провайдер обрывает длинные UDP-потоки WARP; FlowCloud замечает обрыв за пару секунд и переподключается к тому же серверу с нового порта.')
				}, _('переподключений: %d').format(t.reconnects)) : '',
				t.quality ? E('div', { 'style': 'color:#c98a14' }, t.quality) : '',
				t.error ? E('div', { 'style': 'color:#c94141' }, t.error) : ''
			]),
			E('td', { 'class': 'td' }, (t.type == 'warp' && t.state == 'up') ? E('button', {
				'class': 'cbi-button cbi-button-action',
				'title': _('Подобрать другой сервер WARP сейчас, даже если текущий работает'),
				'click': ui.createHandlerFn(null, warpSwitch, t.name)
			}, _('Сменить сервер')) : '')
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
			E('th', { 'class': 'th' }, _('За 2 мин')),
			E('th', { 'class': 'th' }, _('Профиль')),
			E('th', { 'class': 'th' }, ''),
			E('th', { 'class': 'th' }, '')
		])
	].concat(tunnelRows)));

	var actionLabels = { tunnel: '→ ', direct: _('напрямую'), block: _('блокировка'), zapret: _('zapret2') };
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

	if (status.zapret && status.zapret.active)
		nodes.push(renderZapret(status.zapret));

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

function sizeText(bytes) {
	if (bytes >= 1024 * 1024)
		return (bytes / 1024 / 1024).toFixed(1) + ' ' + _('МБ');
	if (bytes >= 1024)
		return Math.round(bytes / 1024) + ' ' + _('КБ');
	return bytes + ' ' + _('Б');
}

// renderDiag shows `flowcloudd diag -json`: every route to one address.
function renderDiag(report) {
	if (!report)
		return E('div', { 'style': 'color:#c94141' }, _('Проверка не выполнена'));
	if (report.error)
		return E('div', { 'style': 'color:#c94141' }, report.error);
	var rows = (report.routes || []).map(function(r) {
		var pings = (r.pings_ms || []).map(function(ms) { return ms < 0 ? '×' : String(ms); }).join(' / ');
		var f = r.fetch || {};
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, E('strong', {}, r.label)),
			E('td', { 'class': 'td' }, [ pingCell(r.avg_ms), E('span', { 'style': 'color:#888;font-size:90%' }, ' (' + pings + ')') ]),
			E('td', { 'class': 'td' }, E('span', { 'style': 'color:' + (r.loss_pct ? '#c94141' : '#888') }, r.loss_pct + '%')),
			E('td', { 'class': 'td' }, f.ok
				? E('span', { 'style': 'color:#2e9a5b' }, _('открывается: %d мс, %s').format(f.ms, sizeText(f.bytes)))
				: E('span', { 'style': 'color:#c94141' }, f.error || _('не открывается')))
		]);
	});
	return E('div', {}, [
		E('p', {}, [ E('code', {}, report.url), report.address ? ' → ' + report.address : '' ]),
		E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('Маршрут')),
				E('th', { 'class': 'th' }, _('Пинг (TCP)')),
				E('th', { 'class': 'th' }, _('Потери')),
				E('th', { 'class': 'th' }, _('Загрузка страницы'))
			])
		].concat(rows))
	]);
}

// TabbedSection shows each UCI section of a type on its own tab instead of
// one long page. The Map turns any .cbi-section-node-tabbed into tabs.
var TabbedSection = form.TypedSection.extend({
	renderContents: function(cfgsections, nodes) {
		var sectionEl = this.super('renderContents', [ cfgsections, nodes ]);
		if (!cfgsections.length)
			return sectionEl;
		var group = E('div', { 'class': 'cbi-section-node-tabbed' });
		cfgsections.forEach(function(sid) {
			var node = sectionEl.querySelector('.cbi-section-node[data-section-id="' + sid + '"]');
			if (!node)
				return;
			var heading = node.previousElementSibling;
			var remove = heading && heading.previousElementSibling;
			var title = sid;
			if (uci.get('flowcloud', sid, 'enabled') == '0')
				title += ' ' + _('(выкл.)');
			var pane = E('div', { 'data-tab': 'item-' + sid, 'data-tab-title': title });
			pane.appendChild(node);
			if (remove && remove.classList.contains('cbi-section-remove'))
				pane.appendChild(remove);
			if (heading && heading.tagName == 'H3')
				heading.remove();
			group.appendChild(pane);
		});
		sectionEl.insertBefore(group, sectionEl.lastElementChild);
		return sectionEl;
	}
});

// ContentSection is a tab with content built by the view, not UCI options.
var ContentSection = form.NamedSection.extend({
	render: function() {
		return Promise.resolve(E('div', {
			'class': 'cbi-section',
			'data-tab': this.sectiontype,
			'data-tab-title': this.title
		}, this.content));
	}
});

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
		s = m.section(TabbedSection, 'section', _('Секции'),
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
		o.value('zapret', _('Через zapret2 (обход DPI без туннеля)'));
		o.default = 'tunnel';

		o = s.option(form.ListValue, 'tunnel', _('Туннель'));
		uci.sections('flowcloud', 'tunnel').forEach(function(tunnel) {
			var label = tunnel['.name'] + (tunnel.type == 'interface' ? ' (' + (tunnel.interface || '?') + ')' :
				(tunnel.type == 'opera' ? ' (Opera ' + (tunnel.country || 'EU') + ')' : ' (WARP)'));
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
		s = m.section(TabbedSection, 'tunnel', _('Туннели'),
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
		o.value('opera', _('Opera VPN (выход за границей, для геоблоков)'));
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
		o.placeholder = _('авто');
		o.depends('type', 'warp');

		o = s.option(form.Value, 'health_interval', _('Проверка каждые, с'),
			_('Как часто проверять, что туннель пропускает трафик. Две неудачные проверки подряд — разрыв: сервер WARP меняется сразу. Качество оценивается по последним 8 проверкам (2 минуты при 15 с).'));
		o.datatype = 'range(5,3600)';
		o.placeholder = '15';

		o = s.option(form.Value, 'max_ping', _('Макс. пинг, мс'),
			_('Если медианный пинг за окно выше, FlowCloud ищет сервер WARP лучше и переключается, только если найденный быстрее хотя бы на 30%. Не чаще раза в 10 минут. 0 — не проверять.'));
		o.datatype = 'range(0,10000)';
		o.placeholder = '300';
		o.depends('type', 'warp');

		o = s.option(form.Value, 'max_loss', _('Макс. потери, %'),
			_('Если за окно не прошло столько проверок или больше, сервер WARP меняется на любой рабочий. 0 — не проверять.'));
		o.datatype = 'range(0,100)';
		o.placeholder = '30';
		o.depends('type', 'warp');

		o = s.option(form.Flag, 'awg3', _('Маскировка AmneziaWG 3'),
			_('Дополнительные пакеты-приманки перед рукопожатием (I2–I5), случайная набивка пакетов с данными, случайный размер рукопожатия и разброс таймингов — трафик меньше похож на WireGuard. Сервер WARP эти параметры принимает. Выключите, если WARP перестанет подключаться.'));
		o.default = '1';
		o.rmempty = false;
		o.depends('type', 'warp');

		o = s.option(form.Flag, 'site_test', _('Проверять сайты при подборе'),
			_('Сервер WARP выбирается, только если через него открываются тестовые сайты, а после переключения они проверяются ещё раз через сам туннель. Если не открываются, FlowCloud берёт другой сервер (до 3 раз подряд).'));
		o.default = '1';
		o.rmempty = false;
		o.depends('type', 'warp');

		o = s.option(form.DynamicList, 'test_url', _('Тестовые сайты'),
			_('По умолчанию YouTube и Telegram. Сайт считается открытым, если ответ дошёл до конца или пришло больше 64 КБ.'));
		o.placeholder = 'https://www.youtube.com/';
		o.validate = validateURL;
		o.depends({ 'type': 'warp', 'site_test': '1' });

		o = s.option(form.DynamicList, 'avoid_colo', _('Избегать выхода в'),
			_('Города Cloudflare (коды IATA), где WARP выходит в интернет через российские сети и блокировки остаются. Такой сервер выбирается, только если другие не открывают тестовые сайты. По умолчанию DME (Москва) и LED (Санкт-Петербург); «-» — не избегать ничего.'));
		o.value('DME', _('DME — Москва'));
		o.value('LED', _('LED — Санкт-Петербург'));
		o.depends('type', 'warp');

		o = s.option(form.ListValue, 'country', _('Регион выхода'),
			_('Бесплатные прокси Opera VPN: сайты видят адрес Opera в этом регионе, поэтому открываются сервисы, закрытые для России (Gemini, ChatGPT, Claude и другие). Только TCP: QUIC для секций этого туннеля отключается, приложения переходят на TCP. Скорость около 10–15 Мбит/с — для видео не подходит.'));
		o.value('EU', _('Европа'));
		o.value('AM', _('Америка'));
		o.value('AS', _('Азия'));
		o.default = 'EU';
		o.depends('type', 'opera');

		o = s.option(form.ListValue, 'via', _('Подключаться через'),
			_('Адреса Opera VPN в России заблокированы, поэтому до них FlowCloud ходит через другой туннель — обычно WARP.'));
		o.value('', _('первый WARP-туннель'));
		uci.sections('flowcloud', 'tunnel').forEach(function(tunnel) {
			if (tunnel.type != 'opera')
				o.value(tunnel['.name'], tunnel['.name']);
		});
		o.depends('type', 'opera');

		o = s.option(form.Flag, 'fail_closed', _('Не пускать мимо туннеля'),
			_('Если туннель недоступен, трафик его секций блокируется, а не идёт напрямую.'));
		o.default = '0';

		/* zapret2 */
		s = m.section(form.NamedSection, 'zapret', 'zapret', _('zapret2'),
			_('Обход DPI без туннеля: трафик секций с действием «Через zapret2» идёт напрямую с вашего IP, а первые пакеты каждого соединения обрабатывает nfqws2 из <a href="%s" target="_blank">zapret2</a>. Устанавливается отдельно: install.sh спрашивает об этом при установке.').format('https://github.com/bol-van/zapret2'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Включить zapret2'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.ListValue, 'strategy', _('Стратегия'),
			_('В режиме «Автоподбор» FlowCloud проверяет тестовые адреса и, если они перестали открываться, перебирает стратегии и запоминает первую рабочую.'));
		o.value('auto', _('Автоподбор'));
		[
			[ 'fake_md5_disorder', 'fake (tcp_md5) + multidisorder' ],
			[ 'fake_rndsni_seqovl', 'fake (rnd SNI) + multisplit seqovl' ],
			[ 'seqovl', 'multisplit seqovl' ],
			[ 'disorder', 'multidisorder' ],
			[ 'fake_badsum_disorder', 'fake (badsum) + multidisorder' ],
			[ 'fake_autottl_split', 'fake (autottl) + multisplit' ],
			[ 'fake_ttl4_disorder', 'fake (ttl 4) + multidisorder' ],
			[ 'double_fake_disorder', '2 fakes (tcp_md5) + multidisorder' ]
		].forEach(function(v) { o.value(v[0], v[1]); });
		o.value('custom', _('Свои аргументы nfqws2'));
		o.default = 'auto';

		o = s.option(form.TextValue, 'custom_args', _('Аргументы nfqws2'),
			_('Профили nfqws2 целиком (--filter-tcp=… --lua-desync=… --new …). Очередь, марку и Lua-библиотеки FlowCloud добавляет сам.'));
		o.rows = 4;
		o.depends('strategy', 'custom');

		o = s.option(form.DynamicList, 'test_url', _('Тестовые адреса'),
			_('Что должно открываться через zapret2. Адрес считается рабочим, если ответ дошёл до конца или пришло больше 64 КБ (так ловится «заморозка» соединения после 16 КБ).'));
		o.placeholder = 'https://www.youtube.com/';
		o.validate = validateURL;

		o = s.option(form.Value, 'check_interval', _('Проверять каждые, с'));
		o.datatype = 'range(60,86400)';
		o.placeholder = '300';

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

		/* Diagnostics */
		var warpSwitch = function(name) {
			return fs.exec(DAEMON, [ 'warp-switch', name ]).then(function(result) {
				if (result.code != 0)
					throw new Error(result.stderr || result.stdout || _('ошибка'));
				ui.addNotification(null, E('p', _('Туннель %s ищет другой сервер WARP. Новый сервер появится в таблице через 10–30 секунд.').format(name)), 'info');
			}).catch(function(err) {
				ui.addNotification(null, E('p', _('Не удалось сменить сервер: %s').format(err.message || err)), 'danger');
			});
		};
		var detailsNode = E('div', { 'id': 'flowcloud-details' }, renderStatus(initialStatus, warpSwitch));

		var diagInput = E('input', {
			'type': 'text',
			'class': 'cbi-input-text',
			'style': 'width:28em;max-width:100%',
			'list': 'flowcloud-diag-targets',
			'value': 'https://www.youtube.com/',
			'placeholder': 'https://example.com/'
		});
		var diagTargets = E('datalist', { 'id': 'flowcloud-diag-targets' }, [
			'https://www.youtube.com/', 'https://i.ytimg.com/generate_204', 'https://chatgpt.com/',
			'https://web.telegram.org/', 'https://discord.com/', 'https://www.instagram.com/',
			'https://1.1.1.1/cdn-cgi/trace'
		].map(function(url) { return E('option', { 'value': url }); }));
		var diagResult = E('div', { 'style': 'margin-top:8px' });
		var runDiag = function() {
			var target = diagInput.value.trim();
			if (!target)
				return;
			dom.content(diagResult, E('p', { 'class': 'spinning' }, _('Проверяю %s по всем маршрутам… до 15 секунд').format(target)));
			return fs.exec_direct(DAEMON, [ 'diag', '-json', target ], 'json').then(function(report) {
				dom.content(diagResult, renderDiag(report));
			}).catch(function(err) {
				dom.content(diagResult, E('div', { 'style': 'color:#c94141' }, err.message || String(err)));
			});
		};
		diagInput.addEventListener('keydown', function(ev) {
			if (ev.key == 'Enter') {
				ev.preventDefault();
				runDiag();
			}
		});

		var logNode = E('pre', { 'style': 'max-height:24em;overflow:auto;font-size:85%;white-space:pre-wrap;display:none' });
		var showLog = function() {
			return fs.exec_direct('/sbin/logread', [ '-e', 'flowcloud' ]).then(function(text) {
				var lines = (text || '').trim().split('\n');
				logNode.textContent = lines.slice(-150).reverse().join('\n') || _('Журнал пуст');
				logNode.style.display = '';
			}).catch(function(err) {
				logNode.textContent = err.message || String(err);
				logNode.style.display = '';
			});
		};

		s = m.section(ContentSection, 'settings', 'diagnostics', _('Диагностика'));
		s.content = [
			detailsNode,
			E('h3', {}, _('Проверка адреса')),
			E('div', { 'class': 'cbi-section-descr' }, _('Пинг (время TCP-соединения, работает и там, где ICMP закрыт) и загрузка страницы напрямую, через каждый работающий туннель и через zapret2 — сразу видно, какой маршрут открывает сайт и какой быстрее.')),
			E('div', {}, [
				diagInput, diagTargets, ' ',
				E('button', { 'class': 'cbi-button cbi-button-action', 'click': ui.createHandlerFn(this, runDiag) }, _('Проверить'))
			]),
			diagResult,
			E('h3', {}, _('Журнал')),
			E('div', {}, E('button', { 'class': 'cbi-button cbi-button-neutral', 'click': ui.createHandlerFn(this, showLog) }, _('Показать журнал'))),
			E('div', { 'class': 'cbi-section-descr' }, _('Последние 150 записей FlowCloud, новые сверху.')),
			logNode
		];

		var statusNode = E('div', { 'id': 'flowcloud-status' }, renderSummary(initialStatus));
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
					dom.content(target, renderSummary(status));
				target = document.getElementById('flowcloud-details');
				if (target)
					dom.content(target, renderStatus(status, warpSwitch));
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
