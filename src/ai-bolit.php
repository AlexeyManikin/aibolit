<?php
///////////////////////////////////////////////////////////////////////////
// Created and developed by Greg Zemskov, Revisium Company
// Email: audit@revisium.com, http://revisium.com/ai/

// Commercial usage is not allowed without a license purchase or written permission of the author
// Source code and signatures usage is not allowed

// Certificated in Federal Institute of Industrial Property in 2012
// http://revisium.com/ai/i/mini_aibolit.jpg

////////////////////////////////////////////////////////////////////////////
// Запрещено использование скрипта в коммерческих целях без приобретения лицензии.
// Запрещено использование исходного кода скрипта и сигнатур.
//
// По вопросам приобретения лицензии обращайтесь в компанию "Ревизиум": http://www.revisium.com
// audit@revisium.com
// На скрипт получено авторское свидетельство в Роспатенте
// http://revisium.com/ai/i/mini_aibolit.jpg
///////////////////////////////////////////////////////////////////////////
ini_set('memory_limit', '1G');
ini_set('xdebug.max_nesting_level', 500);

$int_enc = @ini_get('mbstring.internal_encoding');
        
define('SHORT_PHP_TAG', strtolower(ini_get('short_open_tag')) == 'on' || strtolower(ini_get('short_open_tag')) == 1 ? true : false);

// Put any strong password to open the script from web
// Впишите вместо put_any_strong_password_here сложный пароль	 

define('PASS', '????????????????'); 

//////////////////////////////////////////////////////////////////////////

if (isCli()) {
	if (strpos('--eng', $argv[$argc - 1]) !== false) {
		  define('LANG', 'EN');  
	}
} else {
   define('NEED_REPORT', true);
}
	
if (!defined('LANG')) {
   define('LANG', 'RU');  
}	

// put 1 for expert mode, 0 for basic check and 2 for paranoic mode
// установите 1 для режима "Эксперта", 0 для быстрой проверки и 2 для параноидальной проверки (для лечения сайта) 
define('AI_EXPERT_MODE', 2); 

define('REPORT_MASK_PHPSIGN', 1);
define('REPORT_MASK_SPAMLINKS', 2);
define('REPORT_MASK_DOORWAYS', 4);
define('REPORT_MASK_SUSP', 8);
define('REPORT_MASK_CANDI', 16);
define('REPORT_MASK_WRIT', 32);
define('REPORT_MASK_FULL',0# REPORT_MASK_PHPSIGN | REPORT_MASK_DOORWAYS | REPORT_MASK_SUSP
/* <-- remove this line to enable "recommendations"  

| REPORT_MASK_SPAMLINKS 

 remove this line to enable "recommendations" --> */
);

define('AI_HOSTER', 1); 

define('AI_EXTRA_WARN', 0);

$defaults = array(
	'path' => dirname(__FILE__),
	'scan_all_files' => (AI_EXPERT_MODE == 2), // full scan (rather than just a .js, .php, .html, .htaccess)
	'scan_delay' => 0, // delay in file scanning to reduce system load
	'max_size_to_scan' => '600K',
	'site_url' => '', // website url
	'no_rw_dir' => 0,
    	'skip_ext' => '',
        'skip_cache' => false,
	'report_mask' => REPORT_MASK_FULL
);

define('DEBUG_MODE', 0);
define('DEBUG_PERFORMANCE', 0);

define('AIBOLIT_START_TIME', time());
define('START_TIME', microtime(true));

define('DIR_SEPARATOR', '/');

define('AIBOLIT_MAX_NUMBER', 200);

define('DOUBLECHECK_FILE', 'AI-BOLIT-DOUBLECHECK.php');

if ((isset($_SERVER['OS']) && stripos('Win', $_SERVER['OS']) !== false)/* && stripos('CygWin', $_SERVER['OS']) === false)*/) {
   define('DIR_SEPARATOR', '\\');
}

$g_SuspiciousFiles = array('cgi', 'pl', 'o', 'so', 'py', 'sh', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'shtml');
$g_SensitiveFiles = array_merge(array('php', 'js', 'htaccess', 'html', 'htm', 'tpl', 'inc', 'css', 'txt', 'sql', 'ico', '', 'susp', 'suspected', 'zip', 'tar'), $g_SuspiciousFiles);
$g_CriticalFiles = array('php', 'htaccess', 'cgi', 'pl', 'o', 'so', 'py', 'sh', 'phtml', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'shtml', 'susp', 'suspected', 'infected', 'vir', 'ico', '');
$g_CriticalEntries = '^\s*<\?php|^\s*<\?=|^#!/usr|^#!/bin|\beval|assert|base64_decode|\bsystem|create_function|\bexec|\bpopen|\bfwrite|\bfputs|file_get_|call_user_func|file_put_|\$_REQUEST|ob_start|\$_GET|\$_POST|\$_SERVER|\$_FILES|\bmove|\bcopy|\barray_|reg_replace|\bmysql_|\bchr|fsockopen|\$GLOBALS|sqliteCreateFunction';
$g_VirusFiles = array('js', 'html', 'htm', 'suspicious');
$g_VirusEntries = '<\s*script|<\s*iframe|<\s*object|<\s*embed|fromCharCode|setTimeout|setInterval|location\.|document\.|window\.|navigator\.|\$(this)\.';
$g_PhishFiles = array('js', 'html', 'htm', 'suspected', 'php', 'pht', 'php7');
$g_PhishEntries = '<\s*title|<\s*html|<\s*form|<\s*body|bank|account';
$g_ShortListExt = array('php', 'php3', 'php4', 'php5', 'php6', 'php7', 'pht', 'html', 'htm', 'phtml', 'shtml', 'khtml', '', 'ico', 'txt');

if (LANG == 'RU') {
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// RUSSIAN INTERFACE
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
$msg1 = "\"Отображать по _MENU_ записей\"";
$msg2 = "\"Ничего не найдено\"";
$msg3 = "\"Отображается c _START_ по _END_ из _TOTAL_ файлов\"";
$msg4 = "\"Нет файлов\"";
$msg5 = "\"(всего записей _MAX_)\"";
$msg6 = "\"Поиск:\"";
$msg7 = "\"Первая\"";
$msg8 = "\"Предыдущая\"";
$msg9 = "\"Следующая\"";
$msg10 = "\"Последняя\"";
$msg11 = "\": активировать для сортировки столбца по возрастанию\"";
$msg12 = "\": активировать для сортировки столбцов по убыванию\"";

define('AI_STR_001', 'Отчет сканера <a href="https://revisium.com/ai/">AI-Bolit</a> v@@VERSION@@:');
define('AI_STR_002', 'Обращаем внимание на то, что большинство CMS <b>без дополнительной защиты</b> рано или поздно <b>взламывают</b>.<p> Компания <a href="https://revisium.com/">"Ревизиум"</a> предлагает услугу превентивной защиты сайта от взлома с использованием уникальной <b>процедуры "цементирования сайта"</b>. Подробно на <a href="https://revisium.com/ru/client_protect/">странице услуги</a>. <p>Лучшее лечение &mdash; это профилактика.');
define('AI_STR_003', 'Не оставляйте файл отчета на сервере, и не давайте на него прямых ссылок с других сайтов. Информация из отчета может быть использована злоумышленниками для взлома сайта, так как содержит информацию о настройках сервера, файлах и каталогах.');
define('AI_STR_004', 'Путь');
define('AI_STR_005', 'Изменение свойств');
define('AI_STR_006', 'Изменение содержимого');
define('AI_STR_007', 'Размер');
define('AI_STR_008', 'Конфигурация PHP');
define('AI_STR_009', "Вы установили слабый пароль на скрипт AI-BOLIT. Укажите пароль не менее 8 символов, содержащий латинские буквы в верхнем и нижнем регистре, а также цифры. Например, такой <b>%s</b>");
define('AI_STR_010', "Сканер AI-Bolit запускается с паролем. Если это первый запуск сканера, вам нужно придумать сложный пароль и вписать его в файле ai-bolit.php в строке №34. <p>Например, <b>define('PASS', '%s');</b><p>
После этого откройте сканер в браузере, указав пароль в параметре \"p\". <p>Например, так <b>http://mysite.ru/ai-bolit.php?p=%s</b>. ");
define('AI_STR_011', 'Текущая директория не доступна для чтения скрипту. Пожалуйста, укажите права на доступ <b>rwxr-xr-x</b> или с помощью командной строки <b>chmod +r имя_директории</b>');
define('AI_STR_012', "Затрачено времени: <b>%s</b>. Сканирование начато %s, сканирование завершено %s");
define('AI_STR_013', 'Всего проверено %s директорий и %s файлов.');
define('AI_STR_014', '<div class="rep" style="color: #0000A0">Внимание, скрипт выполнил быструю проверку сайта. Проверяются только наиболее критические файлы, но часть вредоносных скриптов может быть не обнаружена. Пожалуйста, запустите скрипт из командной строки для выполнения полного тестирования. Подробнее смотрите в <a href="https://revisium.com/ai/faq.php">FAQ вопрос №10</a>.</div>');
define('AI_STR_015', '<div class="title">Критические замечания</div>');
define('AI_STR_016', 'Эти файлы могут быть вредоносными или хакерскими скриптами');
define('AI_STR_017', 'Вирусы и вредоносные скрипты не обнаружены.');
define('AI_STR_018', 'Эти файлы могут быть javascript вирусами');
define('AI_STR_019', 'Обнаружены сигнатуры исполняемых файлов unix и нехарактерных скриптов. Они могут быть вредоносными файлами');
define('AI_STR_020', 'Двойное расширение, зашифрованный контент или подозрение на вредоносный скрипт. Требуется дополнительный анализ');
define('AI_STR_021', 'Подозрение на вредоносный скрипт');
define('AI_STR_022', 'Символические ссылки (symlinks)');
define('AI_STR_023', 'Скрытые файлы');
define('AI_STR_024', 'Возможно, каталог с дорвеем');
define('AI_STR_025', 'Не найдено директорий c дорвеями');
define('AI_STR_026', 'Предупреждения');
define('AI_STR_027', 'Подозрение на мобильный редирект, подмену расширений или автовнедрение кода');
define('AI_STR_028', 'В не .php файле содержится стартовая сигнатура PHP кода. Возможно, там вредоносный код');
define('AI_STR_029', 'Дорвеи, реклама, спам-ссылки, редиректы');
define('AI_STR_030', 'Непроверенные файлы - ошибка чтения');
define('AI_STR_031', 'Невидимые ссылки. Подозрение на ссылочный спам');
define('AI_STR_032', 'Невидимые ссылки');
define('AI_STR_033', 'Отображены только первые ');
define('AI_STR_034', 'Подозрение на дорвей');
define('AI_STR_035', 'Скрипт использует код, который часто встречается во вредоносных скриптах');
define('AI_STR_036', 'Директории из файла .adirignore были пропущены при сканировании');
define('AI_STR_037', 'Версии найденных CMS');
define('AI_STR_038', 'Большие файлы (больше чем %s). Пропущено');
define('AI_STR_039', 'Не найдено файлов больше чем %s');
define('AI_STR_040', 'Временные файлы или файлы(каталоги) - кандидаты на удаление по ряду причин');
define('AI_STR_041', 'Потенциально небезопасно! Директории, доступные скрипту на запись');
define('AI_STR_042', 'Не найдено директорий, доступных на запись скриптом');
define('AI_STR_043', 'Использовано памяти при сканировании: ');
define('AI_STR_044', 'Просканированы только файлы, перечисленные в ' . DOUBLECHECK_FILE . '. Для полного сканирования удалите файл ' . DOUBLECHECK_FILE . ' и запустите сканер повторно.');
define('AI_STR_045', '<div class="rep">Внимание! Выполнена экспресс-проверка сайта. Просканированы только файлы с расширением .php, .js, .html, .htaccess. В этом режиме могут быть пропущены вирусы и хакерские скрипты в файлах с другими расширениями. Чтобы выполнить более тщательное сканирование, поменяйте значение настройки на <b>\'scan_all_files\' => 1</b> в строке 50 или откройте сканер в браузере с параметром full: <b><a href="ai-bolit.php?p=' . PASS . '&full">ai-bolit.php?p=' . PASS . '&full</a></b>. <p>Не забудьте перед повторным запуском удалить файл ' . DOUBLECHECK_FILE . '</div>');
define('AI_STR_050', 'Замечания и предложения по работе скрипта и не обнаруженные вредоносные скрипты присылайте на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<p>Также будем чрезвычайно благодарны за любые упоминания скрипта AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. Ссылочку можно поставить на <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>. <p>Если будут вопросы - пишите <a href="mailto:ai@revisium.com">ai@revisium.com</a>. ');
define('AI_STR_051', 'Отчет по ');
define('AI_STR_052', 'Эвристический анализ обнаружил подозрительные файлы. Проверьте их на наличие вредоносного кода.');
define('AI_STR_053', 'Много косвенных вызовов функции');
define('AI_STR_054', 'Подозрение на обфусцированные переменные');
define('AI_STR_055', 'Подозрительное использование массива глобальных переменных');
define('AI_STR_056', 'Дробление строки на символы');
define('AI_STR_057', 'Сканирование выполнено в экспресс-режиме. Многие вредоносные скрипты могут быть не обнаружены.<br> Рекомендуем проверить сайт в режиме "Эксперт" или "Параноидальный". Подробно описано в <a href="https://revisium.com/ai/faq.php">FAQ</a> и инструкции к скрипту.');
define('AI_STR_058', 'Обнаружены фишинговые страницы');

define('AI_STR_059', 'Мобильных редиректов');
define('AI_STR_060', 'Вредоносных скриптов');
define('AI_STR_061', 'JS Вирусов');
define('AI_STR_062', 'Фишинговых страниц');
define('AI_STR_063', 'Исполняемых файлов');
define('AI_STR_064', 'IFRAME вставок');
define('AI_STR_065', 'Пропущенных больших файлов');
define('AI_STR_066', 'Ошибок чтения файлов');
define('AI_STR_067', 'Зашифрованных файлов');
define('AI_STR_068', 'Подозрительных (эвристика)');
define('AI_STR_069', 'Символических ссылок');
define('AI_STR_070', 'Скрытых файлов');
define('AI_STR_072', 'Рекламных ссылок и кодов');
define('AI_STR_073', 'Пустых ссылок');
define('AI_STR_074', 'Сводный отчет');
define('AI_STR_075', 'Сканер бесплатный только для личного некоммерческого использования. Информация по <a href="https://revisium.com/ai/faq.php#faq11" target=_blank>коммерческой лицензии</a> (пункт №11). <a href="https://revisium.com/images/mini_aibolit.jpg">Авторское свидетельство</a> о гос. регистрации в РосПатенте №2012619254 от 12 октября 2012 г.');

$tmp_str = <<<HTML_FOOTER
   <div class="disclaimer"><span class="vir">[!]</span> Отказ от гарантий: невозможно гарантировать обнаружение всех вредоносных скриптов. Поэтому разработчик сканера не несет ответственности за возможные последствия работы сканера AI-Bolit или неоправданные ожидания пользователей относительно функциональности и возможностей.
   </div>
   <div class="thanx">
      Замечания и предложения по работе скрипта, а также не обнаруженные вредоносные скрипты вы можете присылать на <a href="mailto:ai@revisium.com">ai@revisium.com</a>.<br/>
      Также будем чрезвычайно благодарны за любые упоминания сканера AI-Bolit на вашем сайте, в блоге, среди друзей, знакомых и клиентов. <br/>Ссылку можно поставить на страницу <a href="https://revisium.com/ai/">https://revisium.com/ai/</a>.<br/> 
     <p>Получить консультацию или задать вопросы можно по email <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
	</div>
HTML_FOOTER;

define('AI_STR_076', $tmp_str);
define('AI_STR_077', "Подозрительные параметры времени изменения файла");
define('AI_STR_078', "Подозрительные атрибуты файла");
define('AI_STR_079', "Подозрительное местоположение файла");
define('AI_STR_080', "Обращаем внимание, что обнаруженные файлы не всегда являются вирусами и хакерскими скриптами. Сканер минимизирует число ложных обнаружений, но это не всегда возможно, так как найденный фрагмент может встречаться как во вредоносных скриптах, так и в обычных.<p>Для диагностического сканирования без ложных срабатываний мы разработали специальную версию <u><a href=\"https://revisium.com/ru/blog/ai-bolit-4-ISP.html\" target=_blank style=\"background: none; color: #303030\">сканера для хостинг-компаний</a></u>.");
define('AI_STR_081', "Уязвимости в скриптах");
define('AI_STR_082', "Добавленные файлы");
define('AI_STR_083', "Измененные файлы");
define('AI_STR_084', "Удаленные файлы");
define('AI_STR_085', "Добавленные каталоги");
define('AI_STR_086', "Удаленные каталоги");
define('AI_STR_087', "Изменения в файловой структуре");

$l_Offer =<<<OFFER
    <div>
	 <div class="crit" style="font-size: 17px; margin-bottom: 20px"><b>Внимание! Наш сканер обнаружил подозрительный или вредоносный код</b>.</div> 
	 <p>Возможно, ваш сайт был взломан. Рекомендуем срочно <a href="https://revisium.com/ru/order/#fform" target=_blank>проконсультироваться со специалистами</a> по данному отчету.</p>
	 <p><hr size=1></p>
	 <p>Рекомендуем также проверить сайт бесплатным <b><a href="https://rescan.pro/?utm=aibolit" target=_blank>онлайн-сканером ReScan.Pro</a></b>.</p>
	 <p><hr size=1></p>
         <div class="caution">@@CAUTION@@</div>
    </div>
OFFER;

$l_Offer2 =<<<OFFER2
	   <b>Наши продукты:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="https://revisium.com/ru/blog/revisium-antivirus-for-plesk.html" target=_blank>Антивирус для Plesk</a> Onyx 17.x</b> &mdash;  сканирование и лечение сайтов прямо в панели хостинга</li>
               <li style="margin-top: 10px"><b><a href="https://cloudscan.pro/ru/" target=_blank>Облачный антивирус CloudScan.Pro</a> для веб-специалистов</b> &mdash; лечение сайтов в один клик</li>
               <li style="margin-top: 10px"><b><a href="https://revisium.com/ru/antivirus-server/" target=_blank>Антивирус для сервера</a></b> &mdash; для хостин-компаний, веб-студий и агентств.</li>
              </ul>  
	</div>
OFFER2;

} else {
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ENGLISH INTERFACE
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
$msg1 = "\"Display _MENU_ records\"";
$msg2 = "\"Not found\"";
$msg3 = "\"Display from _START_ to _END_ of _TOTAL_ files\"";
$msg4 = "\"No files\"";
$msg5 = "\"(total _MAX_)\"";
$msg6 = "\"Filter/Search:\"";
$msg7 = "\"First\"";
$msg8 = "\"Previous\"";
$msg9 = "\"Next\"";
$msg10 = "\"Last\"";
$msg11 = "\": activate to sort row ascending order\"";
$msg12 = "\": activate to sort row descending order\"";

define('AI_STR_001', 'AI-Bolit v@@VERSION@@ Scan Report:');
define('AI_STR_002', '');
define('AI_STR_003', 'Caution! Do not leave either ai-bolit.php or report file on server and do not provide direct links to the report file. Report file contains sensitive information about your website which could be used by hackers. So keep it in safe place and don\'t leave on website!');
define('AI_STR_004', 'Path');
define('AI_STR_005', 'iNode Changed');
define('AI_STR_006', 'Modified');
define('AI_STR_007', 'Size');
define('AI_STR_008', 'PHP Info');
define('AI_STR_009', "Your password for AI-BOLIT is too weak. Password must be more than 8 character length, contain both latin letters in upper and lower case, and digits. E.g. <b>%s</b>");
define('AI_STR_010', "Open AI-BOLIT with password specified in the beggining of file in PASS variable. <br/>E.g. http://you_website.com/ai-bolit.php?p=<b>%s</b>");
define('AI_STR_011', 'Current folder is not readable. Please change permission for <b>rwxr-xr-x</b> or using command line <b>chmod +r folder_name</b>');
define('AI_STR_012', "<div class=\"rep\">%s malicious signatures known, %s virus signatures and other malicious code. Elapsed: <b>%s</b
>.<br/>Started: %s. Stopped: %s</div> ");
define('AI_STR_013', 'Scanned %s folders and %s files.');
define('AI_STR_014', '<div class="rep" style="color: #0000A0">Attention! Script has performed quick scan. It scans only .html/.js/.php files  in quick scan mode so some of malicious scripts might not be detected. <br>Please launch script from a command line thru SSH to perform full scan.');
define('AI_STR_015', '<div class="title">Critical</div>');
define('AI_STR_016', 'Shell script signatures detected. Might be a malicious or hacker\'s scripts');
define('AI_STR_017', 'Shell scripts signatures not detected.');
define('AI_STR_018', 'Javascript virus signatures detected:');
define('AI_STR_019', 'Unix executables signatures and odd scripts detected. They might be a malicious binaries or rootkits:');
define('AI_STR_020', 'Suspicious encoded strings, extra .php extention or external includes detected in PHP files. Might be a malicious or hacker\'s script:');
define('AI_STR_021', 'Might be a malicious or hacker\'s script:');
define('AI_STR_022', 'Symlinks:');
define('AI_STR_023', 'Hidden files:');
define('AI_STR_024', 'Files might be a part of doorway:');
define('AI_STR_025', 'Doorway folders not detected');
define('AI_STR_026', 'Warnings');
define('AI_STR_027', 'Malicious code in .htaccess (redirect to external server, extention handler replacement or malicious code auto-append):');
define('AI_STR_028', 'Non-PHP file has PHP signature. Check for malicious code:');
define('AI_STR_029', 'This script has black-SEO links or linkfarm. Check if it was installed by yourself:');
define('AI_STR_030', 'Reading error. Skipped.');
define('AI_STR_031', 'These files have invisible links, might be black-seo stuff:');
define('AI_STR_032', 'List of invisible links:');
define('AI_STR_033', 'Displayed first ');
define('AI_STR_034', 'Folders contained too many .php or .html files. Might be a doorway:');
define('AI_STR_035', 'Suspicious code detected. It\'s usually used in malicious scrips:');
define('AI_STR_036', 'The following list of files specified in .adirignore has been skipped:');
define('AI_STR_037', 'CMS found:');
define('AI_STR_038', 'Large files (greater than %s! Skipped:');
define('AI_STR_039', 'Files greater than %s not found');
define('AI_STR_040', 'Files recommended to be remove due to security reason:');
define('AI_STR_041', 'Potentially unsafe! Folders which are writable for scripts:');
define('AI_STR_042', 'Writable folders not found');
define('AI_STR_043', 'Memory used: ');
define('AI_STR_044', 'Quick scan through the files from ' . DOUBLECHECK_FILE . '. For full scan remove ' . DOUBLECHECK_FILE . ' and launch scanner once again.');
define('AI_STR_045', '<div class="notice"><span class="vir">[!]</span> Ai-BOLIT is working in quick scan mode, only .php, .html, .htaccess files will be checked. Change the following setting \'scan_all_files\' => 1 to perform full scanning.</b>. </div>');
define('AI_STR_050', "I'm sincerely appreciate reports for any bugs you may found in the script. Please email me: <a href=\"mailto:audit@revisium.com\">audit@revisium.com</a>.<p> Also I appriciate any reference to the script in your blog or forum posts. Thank you for the link to download page: <a href=\"https://revisium.com/aibo/\">https://revisium.com/aibo/</a>");
define('AI_STR_051', 'Report for ');
define('AI_STR_052', 'Heuristic Analyzer has detected suspicious files. Check if they are malware.');
define('AI_STR_053', 'Function called by reference');
define('AI_STR_054', 'Suspected for obfuscated variables');
define('AI_STR_055', 'Suspected for $GLOBAL array usage');
define('AI_STR_056', 'Abnormal split of string');
define('AI_STR_057', 'Scanning has been done in simple mode. It is strongly recommended to perform scanning in "Expert" mode. See readme.txt for details.');
define('AI_STR_058', 'Phishing pages detected:');

define('AI_STR_059', 'Mobile redirects');
define('AI_STR_060', 'Malware');
define('AI_STR_061', 'JS viruses');
define('AI_STR_062', 'Phishing pages');
define('AI_STR_063', 'Unix executables');
define('AI_STR_064', 'IFRAME injections');
define('AI_STR_065', 'Skipped big files');
define('AI_STR_066', 'Reading errors');
define('AI_STR_067', 'Encrypted files');
define('AI_STR_068', 'Suspicious (heuristics)');
define('AI_STR_069', 'Symbolic links');
define('AI_STR_070', 'Hidden files');
define('AI_STR_072', 'Adware and spam links');
define('AI_STR_073', 'Empty links');
define('AI_STR_074', 'Summary');
define('AI_STR_075', 'For non-commercial use only. In order to purchase the commercial license of the scanner contact us at ai@revisium.com');

$tmp_str =<<<HTML_FOOTER
		   <div class="disclaimer"><span class="vir">[!]</span> Disclaimer: We're not liable to you for any damages, including general, special, incidental or consequential damages arising out of the use or inability to use the script (including but not limited to loss of data or report being rendered inaccurate or failure of the script). There's no warranty for the program. Use at your own risk. 
		   </div>
		   <div class="thanx">
		      We're greatly appreciate for any references in the social medias, forums or blogs to our scanner AI-BOLIT <a href="https://revisium.com/aibo/">https://revisium.com/aibo/</a>.<br/> 
		     <p>Contact us via email if you have any questions regarding the scanner or need report analysis: <a href="mailto:ai@revisium.com">ai@revisium.com</a>.</p> 
			</div>
HTML_FOOTER;
define('AI_STR_076', $tmp_str);
define('AI_STR_077', "Suspicious file mtime and ctime");
define('AI_STR_078', "Suspicious file permissions");
define('AI_STR_079', "Suspicious file location");
define('AI_STR_081', "Vulnerable Scripts");
define('AI_STR_082', "Added files");
define('AI_STR_083', "Modified files");
define('AI_STR_084', "Deleted files");
define('AI_STR_085', "Added directories");
define('AI_STR_086', "Deleted directories");
define('AI_STR_087', "Integrity Check Report");

$l_Offer =<<<HTML_OFFER_EN
<div>
 <div class="crit" style="font-size: 17px;"><b>Attention! The scanner has detected suspicious or malicious files.</b></div> 
 <br/>Most likely the website has been compromised. Please, <a href="https://revisium.com/en/contacts/" target=_blank>contact website security experts</a> from Revisium to check the report or clean the malware.
 <p><hr size=1></p>
 Also check your website for viruses with our free <b><a href="http://rescan.pro/?en&utm=aibo" target=_blank>online scanner ReScan.Pro</a></b>.
</div>
<br/>
<div>
   Revisium contacts: <a href="mailto:ai@revisium.com">ai@revisium.com</a>, <a href="https://revisium.com/en/contacts/">https://revisium.com/en/home/</a>
</div>
<div class="caution">@@CAUTION@@</div>
HTML_OFFER_EN;

$l_Offer2 = '<b>Special Offers:</b><br/>
              <ul>
               <li style="margin-top: 10px"><font color=red><sup>[new]</sup></font><b><a href="http://ext.plesk.com/packages/b71916cf-614e-4b11-9644-a5fe82060aaf-revisium-antivirus">Antivirus for Plesk Onyx</a></b> hosting panel with one-click malware cleanup and scheduled website scanning.</li>
               <li style="margin-top: 10px">Professional malware cleanup and web-protection service with 6 month guarantee for only $99 (one-time payment): <a href="https://revisium.com/en/home/#order_form">https://revisium.com/en/home/</a>.</li>
              </ul>  
	</div>';

define('AI_STR_080', "Notice! Some of detected files may not contain malicious code. Scanner tries to minimize a number of false positives, but sometimes it's impossible, because same piece of code may be used either in malware or in normal scripts.");
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

$l_Template =<<<MAIN_PAGE
<html>
<head>
<!-- revisium.com/ai/ -->
<meta http-equiv="Content-Type" content="text/html;charset=utf-8" >
<META NAME="ROBOTS" CONTENT="NOINDEX,NOFOLLOW">
<title>@@HEAD_TITLE@@</title>
<style type="text/css" title="currentStyle">
	@import "https://cdn.revisium.com/ai/media/css/demo_page2.css";
	@import "https://cdn.revisium.com/ai/media/css/jquery.dataTables2.css";
</style>

<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/jquery.js"></script>
<script type="text/javascript" language="javascript" src="https://cdn.revisium.com/ai/datatables.min.js"></script>

<style type="text/css">
 body 
 {
   font-family: Tahoma;
   color: #5a5a5a;
   background: #FFFFFF;
   font-size: 14px;
   margin: 20px;
   padding: 0;
 }

.header
 {
   font-size: 34px;
   margin: 0 0 10px 0;
 }

 .hidd
 {
    display: none;
 }
 
 .ok
 {
    color: green;
 }
 
 .line_no
 {
   -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #DAF2C1;
   padding: 2px 5px 2px 5px;
   margin: 0 5px 0 5px;
 }
 
 .credits_header 
 {
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   background: #F2F2F2;
   padding: 10px;
   font-size: 11px;
    margin: 0 0 10px 0;
 }
 
 .marker
 {
    color: #FF0090;
	font-weight: 100;
	background: #FF0090;
	padding: 2px 0px 2px 0px;
	width: 2px;
 }
 
 .title
 {
   font-size: 24px;
   margin: 20px 0 10px 0;
   color: #9CA9D1;
}

.summary 
{
  float: left;
  width: 500px;
}

.summary TD
{
  font-size: 12px;
  border-bottom: 1px solid #F0F0F0;
  font-weight: 700;
  padding: 10px 0 10px 0;
}
 
.crit, .vir
{
  color: #D84B55;
}

.intitem
{
  color:#4a6975;
}

.spacer
{
   margin: 0 0 50px 0;
   clear:both;
}

.warn
{
  color: #F6B700;
}

.clear
{
   clear: both;
}

.offer
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #F2F2F2;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}

.offer2
{
  -webkit-border-radius: 4px;
   -moz-border-radius: 4px;
   border-radius: 4px;

   width: 500px;
   background: #f6f5e0;
   color: #747474;
   font-family: Helvetica, Arial;
   padding: 30px;
   margin: 20px 0 0 550px;
   font-size: 14px;
}


HR {
  margin-top: 15px;
  margin-bottom: 15px;
  opacity: .2;
}
 
.flist
{
   font-family: Henvetica, Arial;
}

.flist TD
{
   font-size: 11px;
   padding: 5px;
}

.flist TH
{
   font-size: 12px;
   height: 30px;
   padding: 5px;
   background: #CEE9EF;
}


.it
{
   font-size: 14px;
   font-weight: 100;
   margin-top: 10px;
}

.crit .it A {
   color: #E50931; 
   line-height: 25px;
   text-decoration: none;
}

.warn .it A {
   color: #F2C900; 
   line-height: 25px;
   text-decoration: none;
}



.details
{
   font-family: Calibri;
   font-size: 12px;
   margin: 10px 10px 10px 0px;
}

.crit .details
{
   color: #A08080;
}

.warn .details
{
   color: #808080;
}

.details A
{
  color: #FFF;
  font-weight: 700;
  text-decoration: none;
  padding: 2px;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;
}

.details A:hover
{
   background: #A0909B;
}

.ctd
{
   margin: 10px 0px 10px 0;
   align:center;
}

.ctd A 
{
   color: #0D9922;
}

.disclaimer
{
   color: darkgreen;
   margin: 10px 10px 10px 0;
}

.note_vir
{
   margin: 10px 0 10px 0;
   //padding: 10px;
   color: #FF4F4F;
   font-size: 15px;
   font-weight: 700;
   clear:both;
  
}

.note_warn
{
   margin: 10px 0 10px 0;
   color: #F6B700;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.note_int
{
   margin: 10px 0 10px 0;
   color: #60b5d6;
   font-size: 15px;
   font-weight: 700;
   clear:both;
}

.updateinfo
{
  color: #FFF;
  text-decoration: none;
  background: #E5CEDE;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
}


.caution
{
  color: #EF7B75;
  text-decoration: none;
  margin: 20px 0 0px 0px;   
  font-size: 12px;
}

.footer
{
  color: #303030;
  text-decoration: none;
  background: #F4F4F4;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 80px 0 10px 0px;   
  padding: 10px;
}

.rep
{
  color: #303030;
  text-decoration: none;
  background: #94DDDB;
  -webkit-border-radius: 7px;
   -moz-border-radius: 7px;
   border-radius: 7px;

  margin: 10px 0 10px 0px;   
  padding: 10px;
  font-size: 12px;
}

</style>

</head>
<body>

<div class="header">@@MAIN_TITLE@@ @@PATH_URL@@ (@@MODE@@)</div>
<div class="credits_header">@@CREDITS@@</div>
<div class="details_header">
   @@STAT@@<br/>
   @@SCANNED@@ @@MEMORY@@.
 </div>

 @@WARN_QUICK@@
 
 <div class="summary">
@@SUMMARY@@
 </div>
 
 <div class="offer">
@@OFFER@@
 </div>

 <div class="offer2">
@@OFFER2@@
 </div> 
 
 <div class="clear"></div>
 
 @@MAIN_CONTENT@@
 
	<div class="footer">
	@@FOOTER@@
	</div>
	
<script language="javascript">

function hsig(id) {
  var divs = document.getElementsByTagName("tr");
  for(var i = 0; i < divs.length; i++){
     
     if (divs[i].getAttribute('o') == id) {
        divs[i].innerHTML = '';
     }
  }

  return false;
}


$(document).ready(function(){
    $('#table_crit').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
		"paging": true,
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending": $msg11,
				"sSortDescending": $msg12	
			}
		}

     } );

});

$(document).ready(function(){
    $('#table_vir').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
       "iDisplayLength": 500,
		"oLanguage": {
			"sLengthMenu": $msg1,
			"sZeroRecords": $msg2,
			"sInfo": $msg3,
			"sInfoEmpty": $msg4,
			"sInfoFiltered": $msg5,
			"sSearch":       $msg6,
			"sUrl":          "",
			"oPaginate": {
				"sFirst": $msg7,
				"sPrevious": $msg8,
				"sNext": $msg9,
				"sLast": $msg10
			},
			"oAria": {
				"sSortAscending":  $msg11,
				"sSortDescending": $msg12	
			}
		},

     } );

});

if ($('#table_warn0')) {
    $('#table_warn0').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}

if ($('#table_warn1')) {
    $('#table_warn1').dataTable({
       "aLengthMenu": [[100 , 500, -1], [100, 500, "All"]],
		"paging": true,
       "aoColumns": [
                                     {"iDataSort": 7, "width":"70%"},
                                     {"iDataSort": 5},
                                     {"iDataSort": 6},
                                     {"bSortable": true},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false},
                                     {"bVisible": false}
                     ],
			         "iDisplayLength": 500,
			  		"oLanguage": {
			  			"sLengthMenu": $msg1,
			  			"sZeroRecords": $msg2,
			  			"sInfo": $msg3,
			  			"sInfoEmpty": $msg4,
			  			"sInfoFiltered": $msg5,
			  			"sSearch":       $msg6,
			  			"sUrl":          "",
			  			"oPaginate": {
			  				"sFirst": $msg7,
			  				"sPrevious": $msg8,
			  				"sNext": $msg9,
			  				"sLast": $msg10
			  			},
			  			"oAria": {
			  				"sSortAscending":  $msg11,
			  				"sSortDescending": $msg12	
			  			}
		}

     } );
}


</script>
<!-- @@SERVICE_INFO@@  -->
 </body>
</html>
MAIN_PAGE;

$g_AiBolitAbsolutePath = dirname(__FILE__);

if (file_exists($g_AiBolitAbsolutePath . '/ai-design.html')) {
  $l_Template = file_get_contents($g_AiBolitAbsolutePath . '/ai-design.html');
}

$l_Template = str_replace('@@MAIN_TITLE@@', AI_STR_001, $l_Template);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//BEGIN_SIG 24/02/2018 09:11:02
$g_DBShe = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$gX_DBShe = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_FlexDBShe = unserialize(gzinflate(/*1519495862*/base64_decode("7b0LX9vG1i/8VRyVXdmx8Z17zKVAUloS2ECStoj4J2wBLrblWnYIJXz3d9Zac5VGvgDt85xz3t0dY0ujmdFc1qzrf/nrlcpaff2hs17eiNZry+vOG29rcDPwory38NenhhONwkGzmN/yLrzchvfobW160Wtno7NegfJLRvnobcPx7vJYPBcrXmXFlypG8XeHRz/tHJ5C6XOvnWctQBuPwbfOyMvS46zY1iY8XmOP11fU46+97cEwuG4Og0HXbwVetlhizxS9116uFLAaC5likVUBj9bZoyur4tHMdTe89LsZb+HcX/y7vLh2kd/QfzT84dC/Z/XJd9gY96MAeqQK8ZqXWM3LrFOdK+gQK9B8e3C4f+qdF99WujWoYaF5fHR6xi588HtBkcYweh20bkL2p3j0a3Ejs89ed+MRqltm1VWqq3p9J/v//biPFQz8od+rsCp+/DF5vYpVs4cevIUr1i5/h7SCG6JI86rTHQVD9hO6wp5XnVmBzlTM9QDvf8EKR6PhKBwPBvhkJ2Kjw/4GX/0udZt9LDzgpxqw6PUjXDlnH6686sKlC/jAYcEScsGssg5UV5bUaESvsSnVRjP7bv/sOwzw992jo18P9r+f7p982j/5zl8655273t1rlzchPx5UFXd3d+xv44nVsamIXsfWIbxg0W8XA3i5Avzahm9F9o8NW3MYjio1KjXs9O9d2Sko4MKUQZdy8mG/3XblAMHOwIGC8VmDCVpjE8QuqF3BKvDuHiqFevlxzhfLu3wNpb1VyW+XYm/lzf5arIH4a+E7aQQFKNBSXW5UXFBZ5/yLc5F3WEXaYnaL0NmiuMcqIipRqeAWWmODslCc/f2hH9vQySIQIpzfV/SouIDvsoXF5LWseXsdh7/TH7FfC0WkD5UqbqK6RrbMYXVKbFhKgcOHxQnOHbf41b/Isxd34+/Mp6josJGTT8Be2ln8w4vYhmryscBBxfaBai5V151Yq573rXqVZZ/FYi4vq5IXCo7DCVwFaOfqmtZ/mpTrvzv9q64/YpVps3/pR8FyvdkOWmGb3XF531jP8iUvusjv/LfRcIGoEmFV3QQ6urI8qZU5qtYrBooKq6FU8n7w8g0vD38YrTJ+Y0kgd6tEyrNettde8rJsqpu0XrzzKOrgPDfggHuoVR8dbOwhGA7DIYxsOBx1+tdetsw6sE20tecP2DGCWxc3bAUoWqVcgcWZ3KPU0oYkm0gzG/pPoJ3yjncBRTtXeMjwq1mx6ySNqACRWC2vOzSgsVHcno00qLG+4DSCFke1HD8iWF+/BsOoE/Z53x041ovsw4EjB8Z2m504QXMwHjVbYX8U9EcR7qP81nan3+qO20Ez7ONxzq6M+91O/xa/18v1zIdwlHkbjvvtomAKqrDd63WY30408ofsbGBlr8b91gj7kGdvOrwfjJrjYRdnvRP02/ggciPsbLHOH74IW9fsQpRpZBw/wu7ji7vq9ZElqa07rXDAzlr3ZjQarJdKrKCkckDzimxkgNQh7cbnYE9VapaDjZ9qcsfjAN7hBo0dYQ/F11vbW+audjUGSPRge8tCQbBr/FBh9eBCqS4JSvXcTgXfRkO/NTKYD7YlttqdQBwD4jTQ28edWq6ptQSrJdqC5rdgN/KvM61YZ+BH0V04bDvQQ5i3aKvBluOWc84WMewV2sH8FvAD5ljyxhidLM52fDqwoVhrRdh6W8C3boklSnxUVdsk21tZ2I7fWSeD4QhGLlvyXp9/eX3BaMJSucyowmtG1F7ntnAQp7cOdOHLxUVesJdZ1nZuC1tHklNb1Vrn8/tKzK7lhGETk7kJ/HYwZGfFz2dnx2xN84Mlxha4RbHmGL9ToOMxbb3phLmKzEtl1UIKcXFtJE9KOJ22GCm6YlO4s/j24qFaqD3y00vdZHeQTk28Qfu3BuRrpaZPDFHJWRkmmK1HVwy6kFOQA1nSRjwv6FEmy14tB/UjDWQ0qQDUCr5fByY9FAWg6gqnLREjLu2uV2wPw8Fl+G3MFg9/xCu2wh6rStBL9gLUX9bN092Tg+MzlEs+7Lzf593lfQUquKJxJ3l2Lt49lAvVShnnw3pqOOo8KLEzFHkOcwhq8YHlnBxMxrmaCO1gKUE9buy+ycvU6uL0lNVmt9bZximyDldg12yJbTMH9wANP8CeKzwm2YfakhDItANOLFfGbvwA/7HDiM4Ed4PfzzeQJ5J7xPvBLWRc9o+TvQ0q1BoGrHNNeVplWRGjBMnAqjdAItfMzjShIjmutDnYznjMESVhpJXKiMFXG0EvVHBggxdcr+hqiwMI1xId7tRWw6HqzhnLxGhdw3U38Cr7QDL5yJZbs2muMKQ/9TWT/mRxa/f8UevGy2ZbN4zMAJ+Q8xjzWcwjB4Yj1Ghc+d0o8HKwzjv9cbBhDC8bvmI+fWq9fAkWlZcrII8kTpxLNuy3G4+Pj6KLgkWyzTEbGGcDlhNbZ7C6gNsdBl851ytpUxFY5oJsQ71/vczZSkMSp3NzS24M9iX2GrEztxg7adeFLIhtVJLrAl+gKmnqDqkDGM1yG5vFfDRgrM0IhlkUyxqPFMw64H3UkVJHmaZaR7kT5kodJDOcVHd5Ol9IPdBuRONLNpRedrVQYa1chWxyYFFw/QUsiwKsiS1BmdtcU4A9qWFPcHQZrYz4y9KzcMYhz0a78uPJoWSnsez50O+3GbsH79piTCW+Ad6BAV5k/1iHiMnmRyHU6ByGLR9267qoVZwmdSRP9arYL2xMmqNOL2h2Oz1UZ7XzXIZP5ThhcKI89NE9/+Kypbsxn7zlLQxvIiFeeRrlqCMdW7adtrqMw4/rDcUk8BWdeVD942OINMXysPYujYmlODGUEjDtngKRP5peVIdVUJa/7lw14Ez0su3OsO/32JcmnmnNJpANt9Tp+ddBVEKGmxV2C1WkovAcfgoFYxb3qX5B/SLJhn5nxbSuKAEYxyWjq/lcUPPh+2QeeuFXdmQPuiFbLG3QqwXFPOj5Mu7v4TjjD4MMW92XnXY76L9yNW0XtkJs2jJw33M0YC157o56gyaMEbBemdmYmQ9UHOZFaQDrQBmrq8aJO++GR24OB1YsCyZQJdbtrBVJ/SmcCqDsJFVqxun02/7Ib+LecgxNGTAEeKT0/E6Xr+hC4pN3kCqLGEvVDG8drSXthmqDT94SisF18wTxG/OMktsfd7tNRpXFLGAdrQbXb22QyhUPHnaZHzFXrW4Y4fBdwbwx+WojY2pQl1BFD5xYkssuogi0kaDhNmGAD7VJARIlFbWSXAzNg+BjHl+4sTmLXIWDoC9XACOyd65BeanQ3bAzCrRS2ruoAVevR4p8vJJ4XZwCPC3XQAXFOIjoNQ47PIGsqpQMvuHqRJKrBsBvwH2UDfzhdSTqtShQXLZA+PrGB73zMold+L2ifa9q32tC9f5odAVOzS8wPmUX7wyD0XjYx4dCIgxLcPACXeDHhJpQQeflbsXX2bbcsZYmo0qdiw/bQpWgFP5ijoVCfBu0CvI28cxqQjnDRLXiGWhakLR5l1JnygKlsvoClawbKIoGUdePboIoqS1RzyXWh6n9XoLjbqWKbBWtlTNWw+LZyc7ur4uHBx/25arBOkGdhaVKacWwUtI+rPCDxfJi2kxlHkAPAf19XcptbdsVObLEtl2ho1dBi2XVtFM8gWs0qUNC6wX8gzvrSadUEvM1vaHNFCovlmukLJ77RcR7kNpwvl7P12U4vNCuWE7VtgjJ4NwHXZRX9FwUmTa2aUbPNeHsYsbOmlWJXb0MZ1G1Vo1JgvO90QOnt3hh4xHe74GbzF7M0sXNXAUwcBU1ZpvbtYDbTFrpsE5lxpRLZRnIf62eon93f3n3O6qLhUp5GTUnkuEqkmafibMXDxU2ZXevG8XXKBJvyJVXfM2niIngDdLESCKzgHWS3kSZ1VD4c98wbrSXCRjRvx8Ejd64O+oM/OGoBJcXgZniCu8HaimN8SQR6/GR+C18b2p1SWhrni4iismmroIQyC64npx5/LnogiyPTQIBXU2qnWa0VTGJy1QExc2Ty0BL15bWney7g7eraz5wllvCVMm7yuW2xJLirwXryqYgdZGp1JQvy6u8LV4/O68Z32woHb6ByoGoNwgt/tx8dEa0hWw+yFk40EwEnbAq2N1eMLoJ241BGI1gaN50+owZYddB5EAh7b0fMVk8j1XA702w5Uhqx+UVWZBJLEJgmZXCDfzRDRhC7bVRTXwrikMWPRqQDK7Y7G/CohFnB9HRoRvecfEfJCBZgguQYOPeQilDmt4SzhCcHdE9I+iS8okQFERT9EgmcgVpZ7U6b8fRQ2OejiNFTrhZTOxwzAQkdp16dZOdT3th9a7IMIMXgDLjvTbGT+ft4pKC2uu8uLnNrXUQUx0O1V02f0BU+e9w2OYTKmyA2E+0/q2lUHZnt/fpnNFtcnTx8l7Jk4pyfLou3nIyeTSZnwe0SjJCMLEkV62cszYZH7h4wd7iHJgy+j7pSa0Y18GsIBmvTSXjMSbtQZ8TtIK6xdekg8U2VKdm6pLeoWXu0fBFUnlpqdJ1c9wYe/6ldJEvcQcRPJhWgIovT6kAjZtF3F6TqgIivbIyybmjyKYgcApx5Xs+97BUeCwKTwtPmOzE6blCHGZcKS2FVIvJiPVVGaAdua5n5rH4uYD+DbBQNRHHlOYtjlqo5CaFMONYjsrSdWE87CqrkXDVKTJepsxIWPlR1E+PZB26g7YcaVPCBsimVkY1OhR+3XDOhbGD1BjiunbCsxVHDQjVCaxBV15tnpePYBmKv06RzXYODiC6gJyUUdK4RSpOrBJ39CrQreUKyfnc7O8JUWx7GPw17gylb8NrrpdOlMWaUK1dX9KpfcM1CIy7YWhYoWM4uWyWwU9ESQA2XQHcLLhyYblwjtIMcw8MXoZdEAZF8Ru7V0dG3nQM5GtTGlpo+oNvjGmE+ohFBTni3Ftk1JBRmQsSKnLIPqOefyuXtyhkvIVW0L++ubr+K0TlbTD8s/XXXduiyZMcmxoaVVlWbDR+V/WFzcGFVM5rzy6yiyYDuArEsFpP25WaLpaPv66JmqK9jT0R0zwZehZSzM8i6fT8Tt/UqpksNXFygpMAho5tgq03yO1txnXUq8uaKwF2rzNgRxEjQ0GfbS7nZP/90dl+c2dv78QhD1NvgShrlPGK1jPL0mXGxXW6O+AcCI5untdH5WeSQkP1vF8r6Les27/gLUmhk2ZsebIGIvPjjxl0DpvtsVbYE7JmQ5yFwPWg4Pl0FYi3cHurMXrDedUIrCOLzYJLomu+1HAlrUuo5rWNpYZVWxWrQmulG8aRKL2ifUfHiZdjK2tDqBIZxeiF7XE3WNyULgw3o16XO8qtokRSpo024wlWBPfzm0bDrVRXvGLZK1bQ78ylk0wsIBe8WUrsViVTLdekW9bjo7VARRWw3K+Vq+SOBqXkfblCMyQLKpluDR3sl+pJXxz28Up3tpJ+8Ql2n5tLNT5W3i7Iq22gSIy45UtfLuRvXDezlJHCgFF7SnvxCx8+Hh6m1tEwflluT+/cpDoXK6IAH2+SmiS5zsBKUm5PKvjgEdXcRPqFc8s3z/PaF3ypk9MBt1TzEycLjr94lpUgHCBxQT/JYtYEOVCpx1UjXlv62YRvWsWDaao0MZGs0NGQj26CbrcZfAta81ax8fzG5/O/0rSLa2iRYDxJNisYM3cjR4xJg1OxImMw2DWdqbX/ccXOlXogbKIe9xPJKh/zc++OeJwcOrwynoJNj+OCFxMUyp7Lu16R218uWxc4h8jwrwFrUas+VaXMxUPzWcFaoNeZKELvmGuwY7uFXBRaz90NcV1nSSrAumxbGZdawsxcZeQWrvalJRlYCY3NaDjwHo5UOToW7ZKzSdqkDJWAxpwM6pUcr+KUzLun48teZwRXiWHhu5yUgWsUS7P8vD3xQLMMI0NSt3Cr2zva/fh+/8NZ8+To6IwYPFXuzZs37v7RnvscPuPlZ7OWPptLidmss9lc+idnszbzbLJRZIOZOsIabf//B/pZA50hSScx2NIXi3E9TonHbnmLTS/y4GwC4dXZKghNIlemkRuXVyln/CjD64rvJ5sao1IVDHoGBfcOk0rgcq2Q4UJopsGeJLfABy/pTuiW2MnNXiTrsf7BOczEkFIHzIOVWuJhdo1kk2qKYZ31hz+J0hAZnPR3SGnOHEGXlSDvUFYTOzAysdiqSh0aWdJakh1bnq1j+j8kf2j3TVjb2IDieGpqbcNZmO+P5seTA1yMBTeIIh+tXmybCO2AuQlYn64614ud/lUoYx08rirSxMe1VYz/NEKJUoQzsalEEKOxILrkwzHLFlc7eLMM811pSIWEm1lfz7gFTT81I9WoigCYxxfpEwUKDcYRbpZZ7bvkEYZd0AjQzETPXJzzj4Hm6Md3OvisVYydLtS9jZhDzRJROLEoUM+59AQroUme2dGc5a/zFN8yYnXAJCYjADygQxmKoSqj4KbHpnAHDW5FIKeMrU2dMcRR4IoV7sSVuBHvasVY/ryQ6xrmCU3fVNZVZW9IFUArsaoLH3kvr3yKgPwwusI+kSENh20srrmpsPvg/IN33G+uEGRUNACrg4IhNz0t7tQ6IDR66IQGwon5Yufud+finGJgLvJZ7zv+xyrALzl5B8slx4UeN4YQaqnm4tdSnjdsqVjGq+KfAn6ypWqdjumP1WyPUW+9uwY7MKtgC25w996YzW5K3SvidMBpyMJvLp1UylUUT1biwxy1/H67E6PzBvuqb2ZcZIKmsAVWfSN8o3E0qsZq4idKh8TiCltF3LvMpWNAFjR7BKdZD1yjJ/eJ8RpOUdRKHSTXfe2sG4VjOPMtPsEFWu25DV5kckiMLO3ZI5gMzwF0BMEa90/2fj55+043qssNw02pr9i/dnDV6Qdt/O3u7ZztHB683d//8O7gw76KkxZjRV5VjGr87Ldu4VSMXvujUdAbjF4pq86jF7PVknbmaye4a0JZYQGFSsHN3XYT9ZHOMIocvXnc54zL4bV7Cy1W+joc3jc7ba0ydrWJJ/65WQI02NFNOGqOBl1XxVG76j0X2J3FTWCLVWeyc9aJMeVF/ClGhPvpplYPE2k+Qbumhh6y1f9rdg2w6BA3/ux9o0rNvnVaN72wPcsD5Xq9LgkX2pOWl+QUNJDaUaxc8e/OIIWAW6QHorJf3O9w4BIBTfOYBWaLd5yxI4NWlzXkFbudS+Rhi7G2+gGgRBy3un+wUvKgFtrb+uKm8pWUqv6yuaWdfeB2PYrdgRmCp+DSASz57Gg4DuRZS+MCKqGlNeA6QDWOpy1omfELkw39DNh7F8Gw+LXh7NKbLZ4xGc/J8PdsOCPWsRJq1jOtG3/ISEXjrtNvh3fR4nh0tbjqYG2jzqgbbLL3fVPiX9nFkmzsMmzfG4c9epBl3Dc3lU20F7G/rjAQZMCE5MCgSt9oXb6QNiLhME6FHEPk9Tw0RrE/UIILvuyXzR/Jc6APSpG+bfFV021zglTLL0iYxFSxqiYb6tTjQo5nxzMyu8kSeFfI9PJFwW/sZhhcwQvR6c9eAb+8KfmbyCYK5tmThsUJ+0nfqbpri7JdvinJGcS1wPkyjLiua2HoYJMJGg2XXt41KFa6ByB7UbggXlYbGMPyOGVYU6somLNnllMjLFbftKKSCtIYoO1wbQIOQDyMq2xu/TkEJjBNuZpXY7Vcdg1BeV532EaDa0RSLHfzacEEzzKHcVM8/MIdoZlZ5e5V4lBwjGqdDRIPkBhnXeKsXe1xFCxBn26ITNwRAY6Sdv47yjjnjnvBCuCfHCzWcyb/5L1FdAuYWBDUH2BSYF9zD1Vw59ninrcLD2T6RECasvBdsToNcP9r8rBobJJzxhZVWS48yp0cc4ZLxKc8iKAAY5iKwtphe0RZJisIm7O0mnCd5eHz3h14LC3DK8oLD7XCY05FaC9QPQJWA/FV2H+N3Z3dn/czp2c7J2cNHi/9eit2d//DHr9HlVBYZ1x39WpOV3HPavU1cEQ0VRWqmcAW6CnJFcFv1tIiRs75ivQiryhWJVl05NIU5iQVktz2iiV0M+Zexht6c3Dgr5VNLUMSFWJOkAItKFO0g6aR8qoO9eHpcoq45h4c/8So6cn+553DQ7f4mlHtfvtgcHkShuB2HvavmoSlxnkmLN4ZBnd+t+ute+vDcV9o7zgADqLsVNcwECFL25pHwTsbvCrwDcBbXDquCjWgCz8wTLPBtWbhABU14ItFlaFM3Obx87ws+1YjhQ4P8dwobqm713+zfRX2BsMgikS8MCw2sd2abG1EBMkA6u+GK26w2fvxx1eJYqib44puDYaGd0F4KjWwkw/aG3tV1i3odYX9kXBzqMihgcMgmmWMDsJoxu2tJ4ddGz5ArDofe9lwkC+V7t0ACSAWcizCSQ9vksFNIIBlZEx6hYCHlmR/bTF/W7A6tySXMFNr2hGB8EOg4mbLoQp8Tax6w0BcQaigyho4f2djzNVMACuav3J65IiHoUheAiEtGd3vwJGVL13kpfQNcSVR3D/ZEmBCb4OEVuI6CQ9Hi0zkgpfbXVHas/nzSGMrScYnWyZOoN9psgnDnrY7EXvBewp8jQRaWJkizHXQpmx0H2HrIHk3mXCZzYE4erp/etoU7pp5R/Sgjm9Q5sH7nghLBeHBi3m8GRIl0HI2y2/3T/ZPhG/Vzoc9T/OhSYtDfCCGrhWGtyiSwU1EPqvgHy5d59jxr/wBE8ACWec6DK8Z+1qkZ+/9fjv4pn7dhKH44Ydd8bUX9cXXod+77LJjSdyBuE35tPh2CUwofDe90xc6Da727Xik9I1hF4ibQuPAx1EYfiYMZEG97jnUwAbtlQTgkKek+yZqse052myHrXEPHbe63OPJK4JYIyYS3UphYouus/GmxJ9ydQmXMKfAozDVTY+WoTdpHXrJhYjl44vRk+ho5NltrksO6cbXJopGyxCyKNyEANoEzpYc4Js0ONcW29Ykh85lxqA6PRlhR07+TfazYTTtVRBXRWEWzFI3Oz5UxRtT6gMPXPoDliUhS4GfUSABASoIZlVfrekIpXI9sXZPfm+enp0cfHhHejpyeezA/lDSZOz4eS2OH5hQLbTIU5K/RezfFFFHr2WUEfuOJm+SMTHuyCwUoeGb/WIkcxw0PmK5Td3blS1YvAirRbe+iOu8mUasaBHWASnSND8A9Qg59ioLv9qW8aCoxEO6s0C8IwmvXufNTW3z6Fcm5Nc2TRAEYbfWC344shTUv9OMr6pQb2v4MHJeisSaocUVEemdDDfmO41iz2rpLtVzWTUN2BKuewbHb08LQmo8Sz7dUBy443lmX9n3DUcp6CUGJ0qAZXbWbifiQ0RYoKBm0BneB+HQL3rBO4WDHGNIOH6nx1H5+NgSEtmqLtURzhyTbPNbGKCNLSqywF9Sj4gHookhJQu8tIdOknHsqiKo6tDIqdyApfjjLcCAfXMLXjHLym1tUpTW6DJarrdhEpq5jYu88NMv5o2QGHoVdHCsxDGOGJEENtVzNlLfgsnifDlwWgci+2N6+WThDQGYBzYY3K2JRy3wFUJIk2V5+CpjhxNNPFSYOMjnrCb0FgnXWOfchCiEMdcdVGk9sUOyNf4bl9Rc0eIFh60LHqBDPamLKJSTAE34+/1rJh2y/qMSgl/cDcEglP/PAzITH1ntzZ13+x/OHkGu6LeHYaftffe/+v3Rdeh9v/TbEFb8dzBiP/4eBR5jTWk9f9iFGcjzWk/GSGe9L+zForwKa/LOTwqH3gX1b0nGkx9cvUdnchBewjYbIXI5KLY2Z+uol+Uc3Xfi3r4Ds/YdmLfvyIblMt750QkuEWttnIeaqSpVB7xkhr0ioCfCa3aIjeQRNeeH2N4bryTejhOT5Rk9JiwRv4y3sCK+JosmZbDZ6t8QyxjdjyBMT1MxWE4BzfC4LbUm08DQdFInVZelEiOlQIK0U45fkScc5wDV4VaT6Jhc05InFYshIApvYO4YoX6S4q9WgMj8+DmggfnFvYq/GO7F2vbVSTfBY4L6slSiqnNbRq9EOB3vleZjkssb7QqYaCr+RT2njgwA7ZCtEOozHFnLmuYrv72VrnaKH1A6VhM/AxGjDjlqE/0hBjKbFVXZyVYusXISLJAaB/Lpv/Lm4CR45VyGarMT7Iq+t8ZMvu6PvFTLowZEbjc3anPB1a8cXxvDnZdNJaOAr20QZrJ2+kRGloHksWMDIdsy3D+JCxbuod2QEXUnQxwxE2xfORnYAIIr9jSjn87SEPJeuZrCtjnceSf42nW84kUsQD0Nu3/CMqJG0VBcX7aIi/vNHSOcwjO5d+2KcZhljvoINwmjipMm1XiKGOsWeVs0pV6S5tdw45GJGDwVpijxlwv2xZRoXSNZCOVXNxw7mRDS9DmEKNR8N2iC4tuOTaIrJQlh1JNGPk6oyQI0H/MttqIR5Cbr5tGvonuLXFaPSoyhAT8Irj7gY2ha2BgXD0i3sFyVMjbWhsbgQ1lyVYGesKHgnCpcVw8mx0VfJGjtz39mbIJ4SK9XKobYlcVNsA8Ow24Q65TubGFsHMRwXYvFKsKjby4331wO8Z+LQ9Ecc5ES6iMoQV6OJNfzL28u8m9K2mMbtgYx3F2POdMpuZQx0rZgTImKOIVVvbp8YkEJe1Rs43G3PDrTm17RtTjAaUgtjOYmAxBBDSZ0YAudN8rzlgiqrvdS7XNlFrWgeT3qN3OLFTVnWpCiRzFZj5oVTVJ6/XRDKba6YsYGGfQQLUDNRgmMQFvqpI4V1GFlv0sPFFJ/cZYHj+34+e2pY19nQvijktYYVy0/sjHuQHyRYd0CFbNCmIerU98YEJYbTUNMSX/TKa8p9pX5piogdYbXt70JSsnltZSjLA4TxCrYAFD9WaPjzl3nAuwc9DdmiSNwwNpy6jFqSHxK3tveUidpihJhVl6noC0h2a2aMBCybmVZv5Toz3uGaQWE4s+JiVQAg5/f2pb4eGKn3eU1rJc4vyaaRqmTUPCS0+xNxbnR24t44Cg2CpK8jCCNpThgvZUiu9wPOgFDgprQucjq6GQmgEGAA5mn6wpbaIaup+EKGft4NrwdS/9RsgTd7iz9t6MJgTj0mL4ZJzyU8oLzz8KKwGiYZRckK5yV8bE8qdGZp7U842MxlsvTQC4rCLZYFXg97IbUWs3cLWEllh6Nsz+JhnixHoXvpCJVsXMoqxExG9UXR796RbpYScjxCMi4bJJRCpPXBHhBdZIRIlDUIICElwiwfZo6k3sqsCXKGYTs+ZfHi/zjBudKQB1JcdnAg6A/H/6S6gD3UUKtnOvbgrYBdPTB5UoU5QGgJMXlikA716nyjCl8VNoyzZMdfsEdtd2a8AuOhtdCxt5wY+MvhgiOrrX6RO0bG6qJ2jCQbq1Kr5jOC1ERl0xAHD63En2E+0WCT6ST5OjjxYT7pKVoLMw/el3mMh23n3oJH6oUaoczWvrWqwwHLZJttKPnlSFuaisdgl+4UJi8i04HJKpGnb8D/RaYgmvlcnn2WqS1m9DuDf9yURQUAMtlKP7a+FaZIBQjixX0WxU5IOxHVf9R03/UxSkjlTZ3N2RmQ1bfi4U26cOuARMLRp3WCzARtQq5FoDc5l8DcPco5NkOPcOcj1T4h53oFjveuuF3W+Nht9npG1pDvMZ2ZjjAzdm6gZWw+/Hk8OgYYiYPkXxhqpYtrrDegvax+YbGMbFiMZ4J6cCP7RAQe2wlfz4i0OMLuWKHQTTujvTOcswGuIlvofWZgKvlNtduSydtqk8bREQkqCCyy1/jYHjPm7J4ZMQNvzmRMCStxLondDNC+eJT+MarRsPYbNgwCuuMfVwUSlNad03Ia9IUvDwhpAd+j5bhtxEX/KEWNl1MQJXOEVLRwnlZawIeSM4Dixs6VlCPfRslZXttGYoatGFErmqlrGvC5fsZPGDWHDN4aSMcV+d3TP2F+EA1Dg/S5U3xUF0x89L7waVMCYbGxTT8ItpptVpLTQg2XX/nQdybc8GlH+MFtCAXiYKGoNNbibST8OzUzGb2pgr8srhGZkWtOfW2BFKdnv5s+tvq/sFSJWsAahup0aZWmOhsWgq1WDH+QqiSqDMZbnuLqF7zq68BB2ntmw0LBMaHWLXa8MqrfAPAMLMT9YwRs92dw8OfdnZ/5VcViU2pCvbgppjNebvE/sYnU60vYpoQ8rUK+OfbRsJbz1h3Rk8VwLk12VxsmuJ9Qk5W/n6Uu3XGquSTE4Zb/y3fExMhWlNLEla2l2Jwmdv18Zn64nh1oDI22CbMF7AllQdWU+C8zRgcrO7r8hJDIiuHUWEEFUMY4xIKotpWV8uGRDHDmrBzlyg+cOHB1GcYwyiF55hKTHzTq5H9TVWjPeWxmCwXL5wcphoCv1V0MiyW10zb0eyc3SKhEUE8/2PniPE0HpbY8oymz8TY0HuhWms1zV42Ac812lKG3sRAi4wmJEATEgsfcOfO0x6SIAzq+bTcJnD1KpRPak44iAUM6NmGl0be+8KeUljHi+zFMZUbemQvcLMASnhbN1225itC0qNKSevEak2LtLruh0Oy3zT9y3Ao02eoFaLJQxhaeTPyW61AC2yGE0YDkXuwDSNw6yluo5rPKD6mxWHTO5DOSVeGWx1apTdr3JW1kMGXXQBP2i6AmzdS5doF/zIKu+NRYC1myLW4801xtlxQvLVeUUFrG3mKmDftwjAMR028W8SEXRCXG9MaIxpyrYLZ2BirYcBlucc/H7Mfh29lWh4M92y8efPm57P3gBhopiOwghxlZKAC1O+Y+EgKiZ5btskI/hahkDRYpBKYykpaacMqzpYmN4WTjQ1zsVDgpLCHQ39p+WV0n7CYBye0C7YCjJSFlXP0q5RvteRV4jaNh7aikHtbspm6/ycWkpx9bTkZy+dl1hU6ZFN2bU7LOPlEgOl6Mgt5HHT94N2n+1Zv7f63Yr6hsNYrBB+9smq6c5MWVYQdkQaBDktRiP1+AAZMgHfzxLP5HLJlj2TcEYzsRcNJlqO00Zi4REMd5GgrMYmBq8QR2EdGpPG84cg9aBFbNnf+GHYTFxKlr5EQrpVD/0ManfI0x3vXXGEud7mHMjaCXcyDN4LgsTPgi4AR5RaL+6Nc7Qh4XV2TqRNNT/V2foLLPWpvRPRnJG0lgjBRfVrsZLZJ/vYivD/nSWg3EYmZqLGAdUrs2gRLWmdTV5OATDoOkObJI33xN2xvpxzxsRi4iMS/mMQWQbjrpOJSO2wGnai+O1PKJ5SjapPGVaTmXk/oSo3bmTgtwLq/9UToj9mORX2KUfGtm6FSLLIfVf1HLaM0iS+vg/R0NSRFFiQVkeF4xG4oSo6Y4cvANVm32vaW3GlABszNhoRBRrls0LHqGVoiKCLOVk5Hio4HIVQLPLyiAZdFrMXE89WTsRjwCNZWxDa9orwgQzSwYXbwwl8VZ4FHL1xSpyB/DJuF71fqGj+L9YMY7tBZzMvQcQw/uNeLfJROZPid9NAWp7GlK0qGXYiC7lXDgoGyMRmrwFopXhXRGvyaYLKhHa+4d3Cyv3t2BHrQ/eOdkx32Vc9gk16rViMsAtTRWzBhsJXchmAp4ImjX3F4Zuc7EON9ta5BsejqOLcI7rQkFQjflAbsygqPjq+KFcsuFngfxAEnzmLklVcmIC7w4AqrHs7TZTXj9NUtGyQxJsq2brSieBbGVIayCtHixOZMT/+Yw/TkJ4UawpOZIj0lKyKiehXt8P86HwdBYDNycoJX0jg4UCoX83FsIWVNMmIsyerUGzUpDzOcf6+ND3ZgJK6ZvpAIE6+SZOF6znqp+Hq6jy7HRXCkrxfnzxCSpQJ/chsYN5QXJy6itwO0gQj+YdfFORVv6Hhv7Q4aw3QmjxonuiaDkFGJ91Ap1DCsH/ENksHkHOMQAWjNB3JbSVZWcDDnXlQ0tq0AENcxJCp0skG0oS8edLPvTnMgtbjwjhtejbg2dkz4vcjFjNccfJLGn2DHwUT0v/ptDP1OxRMhkQX1XYD8J9XoayIh33aWO7F+5yJMjsswtKxe01oAbvO7ljJRXKMQH7kK6sLtiwkYfFUyaYJ/u5BZf213vZlvc5cE8RMhSsChBq4+FrkHI61/3i2MqFmZkO4ZDnwznoTaSEbUxUpuiPPnwZauOSMhcNAjEgHS7qNR0GNbiTJoA17WwnvAor0Ofgrb94zJcTPe9wzETmcWI7PA6fjyz6A1wjJ0nZU6g6BsRzq3JPI8xzqoZ3rmK2FZxEM9xx6mBa5EMUuYhoTVH2VaYTdkzN4PZfzfpndO3sAXMowM+Ap6UT57GHJTXjY0zDLzUdAOW4yVqS8HkX/pSvJtONySn4oKTtmIB/mBE4tDsS6lkhTOEdi3SqLITRiNoJ+UFwZ+Xd4zgTCBMqyjgAlJ4JKdL7esjyAuRQp2+vxLTu54CSsdK+xHTLiArzSYxbwh6mL2egEFAwRNoMGU42gwCRMBvSAG44D64X985sUCdd5cAlybI1JfVgmiFo4nwdq5cZ7fmsxRj7iOsfGkH1VJHFOCqbHstaYjS7U1EU2wea+Z9qQpAG4q6FILjk5Ut72ViK1Oea6QUrsRry1s/RLgpEqwtqspRHx2Mv3c2zqNt1Jrfqogxwrk31bfYyMGG6UtNV430WhECKNE46l1FV76lscThMiuINSMdoEmpCpcH+d1pJzH51N/xnXn8fbUFv5TGtQXOPm80lvX4llJTA9yEzWtKOMhExhViux7Us1URWxOzF6f1ezK8aTQFDkgHf6bJZnq0ou4d68F0GViCslI+LDNXJ5J0zE3Pc90I0XKQG+1JPTBGg95FTUxGK4ZMS6Cs5UqOopfbEYjX1mg8Ew7PT04+sC6gg8D3yrlmYKGIqMVBHQsFW9uLQ0UNuU+vcCyEKK1KCktQHDm1WUeQ9w7Zf4q7AZg4bzDxeuCccMsooTwQtpDscWvtahcm+SZXUVgR0o6H/eH8NrsZ6UcxwCgMprgQZMhMLpka8l3ldYC+MGYD+39zo1vmtMA3mgrO7EypItTJm4bryIiYqVi2pCzatstNi/yuTgrbsSlSqcKKfa+Toi9ok0FSyVIAXJBqyZ/iZhheAhJjUK5AKFUsUgtcoTuNChCqy1CtHBkig0kJ5fgCtzyskb0JN5Z83KFSiF5vVZlN8oFpcposzOkU+AiHf23IXOMRmLzICBjlbyJU0EjOLNqyplGgJuXtCOT+thcMZxv5Y81GG+G/REJNVE8JbRI8ib3UM+MfgnxO8r5+C3r8z5tDaNEXBn9IPcYearLtYR4j/VVyF4MvGdWYsEJmyrmgvSmKIw3IRbx+PBoZy8D3NM6BCN6McMq5aIB63zDqS45hnHW4aGLm/B0BtRUWEXGqAB8LsVjEtFVVRgrLaKbhRUXe+dIkB/pOWDJ9yNQb+k4IaDzODPlih6YUddQYQqUzwSOc2KVfF74sVxMKW5R7ZoPmpa2KuJzri4nDKkp5N4mx5jaDc6X6DwDwneumPF0mOC3Yc0GLPSIsFQfoF7AUf319HZwdNdoOHGGBCE5q2t1O5OXgpRjc0Kd9ZWnVJE4qv6nO2XjERFYFNFzEochUNWOAiTybMGXExyQ1L24Ru4uBkAx7btc+OSl2fMHCMe5gX4/qIiB+sbXUSu4v4+u7gv75D2/f3LCOD9B2ilF7RqqIvxI2CspRFRAXIClxB9KP3/XJSIMZtaFmpfVFqnrLVR4AL4D5kv+XNHxituoWLoboIDKTluCt0MvczxLvGIrilTgdJWATyGh9/ZWmuFjWxndqQhjKd2CShSp3Wd3pEHeRKSWcIBEL0RoSFWOL/oQg8nwiOcXzXvWEAs11SKkWkW2NDxrJLV3Z6SQqU6M0qgipGm1bnNZnRd5IBZc9hQXTkNHkbhLdBkWSmcUDP0Rmxx/MOgKPI7Yclaez5HFK1MuCfTxoSCz453T04ZT5LnM03aSjecQiUAnXzIyaek3ytYL82Ub4utFxG4KsOkmlwtluLx48WpZkCPuky2HiUdEUNYTfF3DrAYlTP52DpqJBFOzRyYIZmOzil/npeO2OvmLIpdVrVvEtDkovSajadMxCchp6jtn+XXNweDZ9b1Ih9T1wgt3caL4aMqOiK1bASBudRZpx70pq8b2+b9y/M9z9iPQbxU4fY2m0PFyw3jcbmAkk37Gaf0C/U9VGAjjsTHYRmCPp4vP4JhmfUUobtzQn+fjRQAES7qrHU/VE4fOVdF7Iqc6B3/7TpDAORGt5omcD4wcvvEzmPwDXMxKjEPPbLEW7rtBg3PsOUrD4lPileGmw41n4CjE0y+mg1xXqwSKR6aKyTZYPoFxK6o6Y24IhBV5JA7BJ2OovSxjfYZBLxwF7A8boeBr0IQkI/qNaxKdsJ6iO+4wMcb9k0IJi+HwukTfFytecdkr1rxir9P3in9GOuSRZ6IbgTvhVcjqHnJ/woqOJ1xF2F5Mopzlkwckg61GLWWGVD5wOGNKEb/xCNeSbkT0rJZqkDuITCoSM2i8Mn0ShMu+7FdVLB5fToueEQSq0FIo1lMgo1R9NdULiqxBZUGsYuntz2rU3VHco1/NEUU12rLaDUog1odVe2vdzqbnJFrPdHr+dVD6cxBcK0PbMOBYtqbAavjGaJW6hxxqej1jLU59xkSjZZ5K2+KhLS08mvbY8ByKm6pUGMl5eXHNX7xCtGh9F4Fs0BqzWbpvcr4EGbGsapzXaBRTI4duqi4hwK97GieaeGAjtbUh24Y9cgTTbqIEV+IKQHtS4skWsoKlQZ5jbJLRTLwUpYoCeyW3zmfAtP6K41aV0Idm3VMeaVASM2VpRcQyUKZNMyEWrIXXLoIYtvMUrFIlYOEVHfhKI3XNr8Gwc3UPdOUrmLjvOm22nyKkfw/F15gFRC8Om83vdnkx3HdSHYf6C8lgeznxvE64HL/NqBvCshG8e0oHBICg2fSAyYr+UBSCVqxtQLA6rz3xEK9YZV6tIipxDQYoDT+OjjQibGLDph0XBsynQRr+AUy4zFyIcDr1nQcPTn+O8r+ZiHBeVSvs1eJQcDjj9CLh0AIKR5OA/mB1kX7woVqolh9Fo865532T6n2lZpmlKOo08BwtYoYk8CJHSxyT+fnPZPUm1GCVQJdX12IgrjNJ5uTaJSiBEFq5w1e6kG/Dn1NVKb7dqEhFwc3fOx4lcefxGAlc42awnGyrEL8QkxsIuxlCrmV+IziB8RsQ30molduGG7hU/8APoQFCoGucIVfJ8awvbBl4We073kv2gLpI9txUXF5PMOZUV0K6eKCqIVXQ5RiE9B4RdYx0ikGb83ECIOqMcw6qARfBQLFdctiKu8hqrYIfO3tPoYSEa6wRFchPr4OG3KWaMk9XFVy2iMbZWXyLCR6qj+iFV6mUy48aUC7bSGopZbX5pf3ikJJMXNO+8ziZWNaJ2ALh/VwWcMj/TD+rU/tZzEvsAF6RjRoht1ddjqfvOjXyd3npUUPkVNAUeBvZnVO2+86aO7tnB5/2+UxWRIfibZhZwKqEzSzTRv/bY1bM6w1YiCPmN0JNsz8e3TQh0KfhUPBaTIWXlx0xxl/Sxd/fe0pxVzR1ZQTEDC7O0pZCYhP3RKAHIXkoZlUXN4N+O3aLDn2EYa7UliQ8mMVBi+82PP7ScTu0EP2Y63usKlDCVCyqGBxK/pJVLSFZwoGpmN/WZyn9B3+imH9zUyUeEvz73pTYLy8lCWaVAxlrq0wtmPMvGxf5Dbaw0H9lSifyWo/Pv3gXFzwvFr2oSOosp1UmP0oPtHOPrq6EgBPfby4eHZPNmYZokzBk9pXwMUUoGFtEglg10AstrxITWoZfQUavFFRKpUqwLI6tSCEcif6DhAHPvGpURJfBZJ/M9sRvKkcfS6GCdhWAk3iSyoZAGeLVyyRRor/eBTSvy3RwuVHBKcDVbpG84wChZNiH0y3ZB52AIJBztapD6Wat3tS6a1UDEoZ996LvXlFzM8fwxFxeDzFVM/2k2nhni/knPS0M07rhtq7jID3Bg9YZBdGoOR5208DfM+gdkIFimfDWvyepESi8goD3AZGC2DhSXIoIFW50kFGJV0qdgADK9SUT6JY9/XHYPWizGeaKiIuGBjMIgb/w6CpPUMce5bk/yOfnPP+6tHjBKb4coTXuyVfyXpPsQekes5zH+B4LQECeQ1zEHzAcGgA+BDNUWCVYOwL2YsI46sgE2HGgjllIanSbQw0LPQ8nB2ccs8k8a+dfGMWz0hujhFIVFfOaPvNK3xgIiiuPKNwRjUaZcleAQ4twhPF4dHQV4WpBXZ9kFOLJGngKU1VMnHZbbCborzileNzGkgzbqCI27RrqlSD0X2TLzLo7hyf7O3u/N08+fuAJVxMoU57CxbTZxbUjkZoiPS5bOTIfd8hqze8PO1+vvt78TYVI3an7fs6q8cr8+GMmVduVaTQyLnEyMR1XK9PIWJRa8CBOLDt6QWFzypVFmV1GNNYzepAn+fGAPV646DglruoubX5gN9fFD+MBcvpJPuHZYRxEyVO2sJ1MDMAhwQi4fHoTG33b5O4dBVZpQl9UCXW1qvBCJQvhRc0io22M/clrCgw+R99xl+SE3KCbdr3H6VaeJFLal8KFWFfsaScoup/87oVwSJTZKJUhH7aIvaGcZoSRlhaxEYBS1UF1lNXypuS2Olfmb/MXe22zNJGIWCFbDhATBUxI8FWU4GOP5yb/foi3JmoyrzfMn2iHJNnGJRdqDKt9Ul1pxf7hgYh1Fg0B5qVYf3CiEQe3Dvlx/mcmOqkVeOZ0T20z9oBNL/GUF3FEHc6cE5WctonFrZNY4ceWESFA3WkoUU2ciBcb3Fip2EmpWCI+ywiacnQ6iKDAaDw1fITFu2/Ejqe0bD853ZkIYgzPv2xf5IWYlUxNNVM1G4/cSXJ73O92+rdGwD/1vqZ8C2N8BFLAL+xDOBVoxFxyO1Kf9uApbYNgMnRnb85aUFyEhx/ncz1i4YCVG+e8rT+lacWpINZupTLzoJmlslvriZYh2/mjpXVEi8bz+PzL1kVerjnSAaIcJWxOlDy95P2Qx7+/dP7sBgD48Tm4ZJ/HPx+zz9OboAuMWrVcWcJS7b8HN9uXt+JcHI7ZB0SgvP1JXGqFvdIvlT+DA612Ha5eiwSWTibQH95RlICWy4mOmu5vqpKNWPVW1ycjgfmkgkYrMVcRa3cxcUx1KdHd1GU/O+g9GeySK1myQHN7A9pr3rBVp8pYb5vjn7itXFCycp8U5AZRGHOoAuTxqrYZ8CP7nCRGAFdeI3H1PHFFvvCjrd88Ehi6wiNq097QrNVc1wXr/ZSllajdMwJ10Gofv4idp/W3qhJdGetP+NK08x4Xp62vkdwEpM+bs2w830b8zWdemhPamM+8NqE+rnbkJldbiceLPC6x7WmzaG+CrIr6vpWTFicfpM1YnkLt2L+6dQan7FI9Gsi6Siet2dSl/4/VCo6yqZtl2stLb1xL3eXE82+MMrG6YcuILWolMqDI422Bb3fq0kiSHuX3PeOwkNl2yjArWsqE/Mjan5QHYkDotipjqPj/RK9naUJtGkSrXqnXpm+aCYQv7daUHZX22JTz8AkdmXzL8PEUduVo0FWHxaRNGGNeocBihX85Ptl/1zw9Pjw4a344au6/Pz773Ziryae10c/NmU5u+0aZdZtBpYs1Y6VYT/ZOb9DV+Dw1zRNIlKWiScMotUYmwZj4jGzHiP8wCROJEIhdDtl7Ehg7k1TdWRIvShf5EtfdCjmOsLbLFdsu4vOkbVXZd+3ahXXh82fhDEwy5+q+OSpp1Ztzkc4L6dQB0+DUykkckmhu7sHGgmuK+xes8JkVNUyWPSYrRHedkb5lnyeCQI0txvNouL2J+JP4BC+CIpnbUPTJA9MKxYs1OQ6LObl4v9MOLrWkDPo9cnO2rwm+WrQ1whdIXSQBSBXZ5hii+H5oxM43HC7OjEdjBNz20sj9syQ4E92eKn5l7c0MjP3zlwl0aXtrmtyvNr+2gTF372pSVTHpxH3S3IE3iraDZjisUsndnKQSqOOjMQBc7UZN4mAIZCJfuJJqFVAAunZtE1GRcJN1kRGWN7y7/LoBSmTWhLZd40rHrHeeR9GgZF6SEKTxyTS2JOb71aUgfeEo+K1oguYGFyFACZYLjzEaKN2seWsYZbqWFLriDiRiRZn6Cg1RPxY4EsV5izgdNqGgY9XrmGUxFsCSfCnZlp37mFhghtNVG7ZVFRWvhsw43GfeeTrXlNMXAiG6rySiXf8B0hifpn+XNE6ljDgeCOle4f75au+Yr9KYKbth2shj6o5n6WzSJpMA5TFBbrvz1YvynTYZtYEZyL7x2RUe5MXdD/Joxhe/N3nqbgzyyj1U2b5+QwHkm3zhsR3zpqQuvSmxZnjTVcyFWIuvo0li2hQRbk6th21OX6or03SPc/bkX6pxkshl1xtO6kM2Ruq2CLkzQfenqFdptaB7o3IRgRKYmHAht4XfyVoIJhd2vDwKbxXDs0B0uQQZ2FSS6Viq8OTAqcwxVUKr56YE3AoeJWWpl+uL3PEPdhrcLsn79CjwTEvgUw91Cxca8oxSKh5zWcWKUj3kgo30927Q7IMQ2Yh7RUq3xAf1jQ0WZWO1TeaMWkAbD8/9waAz6EDcuglatyTArhKUJ+Pjs+8O3jIi5KPaLrf1EufTXQpJQxeWJSPzkj3j0rPEhZn4EJGqTQ8r1qwWBXFRqopy840BOmX+ZgyDfjIh0FVNZM6Le8lpcCjEdsSigg1fVcoa9CP4sPEQWuuD9AUxvfXnShIkBzuGCNTV2jQDohc3UmHshHDn2RL+zOkELg77ivXEKwK6xOdCVhmnXjyphZF6fRL1tPFmiJhdrS3HAQ51d0u6wN3qCENI5iLXI9uTRfIbiDg8xxk1mbjPRQ+maYMJXrtmwBTmWxE6PXSMuKq8Z8DxUHvfel2xbBvWiGGEqaE/CVwQXyVD0Qg9JULxQKdn5KfWGXytWRx8GZwrEzSKf1l6F91LE4vRy9fwyKjNG3xm504bs/HE2Ar4BEaDoNXxu60bfygFklkkleQJnSb44CHwf+urEZtxRSlUgn5bzGldhJzGCJhGalrdwB82r8Ju20SmsOgvDMRgyNSWXtzyTGKEwLAzpZZi3t6ibZiGPa2AzT6V0ntbXQIg2nQNIb2K/V5CQ6ioCiqhLH4ds1uLZjdPpth5NPig1NFetD6bV7VO85fQbCw3wTfAlrS2ZTfSpNk3dFNqXDg0+DsbCz1BTih4Uw/CZQv8pxSUcfofamXKN6HFCTMSv9XQzgXhyLWNnqh5cMDSjmy6SyenZ7DwCC+/mlw1yeXHwaPF5PACsfVkU48ikHylNs36Sa9aTbzpNJmW7EXc5SKXt+aZVi4inC1G7PdqxWpLehmRN2tZZVbvO3VEZ2d+RltqeU85c9P2Qa6yViau0uJn8xQ44IK5PTdoKoYdCNbiFW1HN34lfd9bpMmG2vRoUrIodabaabQtSq+NfOVKcrHpVsb53t1q5ismX8dcBoseicI7TAgMh5DFlDda0cv/S72Sm7GGaOr12Tbj82wVCcHRPnUPuHQm6pmnbD/9rUHB5uHZBYaIhNHBk8i3eDElWxqq5uC1tbQJZiVJ00L8mWQJi6lBPFTi/RW/k1YHNX81AYWpoF41v24YOasGOJtKOdGRNxYUol+E6yhNJe4QTAgTtqhnqAwCN+uYi47IGMV/SvdssQIoI6DECWleXjbR7bU56I6vO/1ii23/SAGGyJ0DcCKQPJiwVsCqcROGt5ZmEhBj5oFt48xQ3QT6pvd6U+3gH2tMS69pfS6BOzmJxcB4/DL/Uos34yvx/3nN6GQX1XkVI0LA+0fcfGkVOqwcX4XTSiV81NP0KbrTL9fM/v9+v7MrpqU/EF8RywIN9PleLTYfm3mVg/E6XqAL/EVXMGHM6kTvDH1OGhJCXF8kE/LkWKfF1qnJYwWtWDABnlO73VFv1m6lKRtmrSRN4qhhSoV6ZfKUzDz1GCao0xLOz9B1Rmjk9bj7jGdklvh/yXUmOWaTPGhqmITCyFCHsfu8y+7xu5NBu6MUw9zIkkhPB4/kROB9DRNC1JbjpujESosr3mYeDzwTTETndApqnQyTzRYZJhC9huBRxIOq6vgk26k2bEwCiJSbdMaqEuR85kdpdmnoQQpbRcSsTj8a+fRkwg1Ul34Mn9Ac4WVp3CZHvxK1USsoy1QQIIAd5Zg0ThgnzuVcOuwCpEmETI30GOIKrIpkuA2OByMDEeN/Z8Kx0GEQchuEC8Ml8QqlhVxRqxswBKLXiyAiBn12pZj/50yRFj2u2B+oMVxeMvfH/6266/+LX82ulq9h1oTaWv2f5cCsr28kTyWgjJeVAqbCc897epFl2pTAZtyHkzT18W1JE7Mi/HkJayQ2/SVTJLPlF0+jAjA0TEahbM7R7OK3KUJoqPa4VE1nwaQ0o55+cVfzCWvMptAwJSEoaR3h9Omk+VmVPn0/vCqNo2HpstMvBf2v4AQrmVFdMzvnmzb5s/DYmnxLk02axqak9GG2k2PS8WDYmGg81jSdEz6i8mvBqzS17GoxngxwmsBpGY7mBr42YQpaahAnd5aKIepUIeW7OFqrxOJVX+AIczDR3xQ/l5exDphGFU1fqesm0z2nvSdoKEuWh6arKPWnpI6SBh7V7OU1I9ma4IEkD21LtjYt8QnyfUqzQzwxbDyaz/Gw69nY2wdZs04GaNXH2Nn0olCQljzmilhGXyGeAAx6dgHOPtHWeqmEsk3+XGlNkVv1FtgHQKGCtlIKPnypEgqF4YgFQE3RE3yy4s5eTBYVulmhFaM1a9KE+dxu4w5lKW63dgvN05tRZBhTNtSqK//HxEUl5f8n13f+Ol9a/HLxrDrsxLxKmtrlf2pUpzoFEjqyznsJrEzrIX128nF/9tIWW/sMxiVGXmBnNy/HnW67SaksopgvotkWUKpNY3OZ75+uNOWsS+D3iP3/NuLQ5cn9qtch6Veq8JA4+wUs5iQ+gJYECgqrZtrZeUNF9JS7nX47uo9mcvZJjE2MXZ1B9G0kOVLTKwF9j6KRP2r5rRtVs4XdncnhSJuKmd4T9yFNxaSYWW0+KKkcO1xt5mFrq3ajmsXxZJIzkKa/Ul8TNVNVC4av5oRaDX9mVW3iwLKvUs2EzRkPxN5cW9FUu8b8palRYqt1u9MDstSEAQYA0q/+sONfdtURNj1+wNQoaEd5sl176I5VbkyE1qkmYNP3/OtOi1GocBREzeuB8n3STCJJYjODC0ViqtIFB4McGXOzhj79OiTZbI7h1pF4nq4+b+rqk3Nopz6p1HWCQjtRx3xQEpSVII2I2+fh+RAX0kCq2/7/ze7xOdfUvJqh9lFbVZjQpL4S9xR/UTHsxe7NAm8Tjio1MTZTSXSS4f4nHpndK9Riy54UsIkMmN3CTEcBz2dCHH+tonxYE8l98mxb/hSObEuqmNeCW57pomQjE3roDCaE/p60o2ryFsfntTfy8mbUeU+U9FL24O5JIBZ8i4K0vFK2YFHyNWTf5QmlufQM5onBEjRUMfVtCGVpB1f+uEvc/d9hP9DlAttDMdFhKm2eVYKZVySZtF+Bo+lWfv7t223ZGPT1bqXyLTEN3crSUZKjjdf/1A3xonWxnX7JBJ1bYwGlDwSwd2UxIP7lBNZlPclMywv/aSRuTsOtqdVIU6PZ6/5JbEQwFfLqBh1jJvXpjJ4I2vDvQNlwKlAXSSqnsX/zbSDDYVYTM+EwvQxGd0HQL+YhCWF/BHStH0I9VwBiy+sR+QpB4Qk45JDiuUMJB0t/RmHf2JucOsL1ZtCfjLSpM781yvugn11g5gVDL34cozMj+yLQ0A9D+v3Z73Y17KHUYU6/M82pz/xV1p+f/dG40gBzHy1XVhQ8v5U9ssTheXH5fAaXtRl3mkWkJ1ji1CnUFBiadx9mjn92n+22HCsfvfvx5PDo+KzJ/njPCDfUq8LQZ8sOmrOKtwf7h3uns3cqbf6e8DYxMsPX3YrIxhZ3gDYXXhbMTqOb4fh78C1ofY8AFriJXwcgB32P7qNR0PsOBFJn3Z6qtzZIAbqf1SsvoWJNgC1P4PuIiiT4t3l8/hKMmmI97beU8UOXje1RVnbhfFK7OlE+/7JwkY8z11OrjN+aTfTkS21NwJ6jCzq78Z57MgXf2IHSpivXQZMvBhjswfiSnS2ecVBhfokdg8pqmqitF4r4j/ceU4xBYh41EYseaa0j1vnd1odx79ICRZbCH1GdFQEe/SLy48R7adqgeQS8mZx3nr9JzaVu2aB2PRNp1tmuneplgRXB5kZcpR5m30otmOSHCY1pMJ7BaBAT5rk5fxojhPZYUBPvHB/vf9jTl9P2KByn+MxboyUnWirqVb6mFe2fBqQO2U++5ATOFp8XnVpjqrjqEqxpLfpmtrX4z0K3eajzbd0pIFExHPuMgoHrADfl580sOSoZD7vFU+Zch6/glwQ3w3flY6gz8ZjBjiCQdDY2MhBaYuK5zN4Nt0ajQVKQTlahGyZF02iZXFr6H1Qfz6oQml1vPF36/z9EYfw/168J+iqxcpa5u/EXfVmbq9SNr1Lux4FAs1t+gy3OH1sNPdc0X5vsc4FaIRS+1dkV0dEzUGlnqDcpxs+sn1EB0Xf5iXoBM6IUnjjt+cPRfW19fRi0O8NARRKTL02U5IfrBPlv2pf/GZ+D2JwnN58FY9VLI/tp0QE7uk9AOrSjOkUt4XnWx86/PFzkrfSFe9edf9m8yBu02yypOxbGiCQJB9YjN+UpzRUHcxgumcwktJeeesEGNuTFtQuaPThlPAxsqNkXicU3dJJK5LnLT32bxew+gdTNEE2SYieHVWPn3BG7nw8Im5PUSltBR3JS00A8SjOUiekwiYFbKid0hNlSafKuJf/x+BpLEx2eLG+wf+Nh11yAbNNseAsPlJe6vLhGmaMvINXzYy7vEJFIuwu+rCarick2q8srTwZjSwtFs95S6oHZ0Nn+B8HZapgclKebgnTDwb1ni5Cyoa8kXlypJLTYPOtFjcJhstHKStUSwAyFFb3NCmWBTUe4bdrY5+gEPjw3B0Vdr6Mmlo2dQDfnSiMj+DlVyk3V0khX0qRKxbyVrkd9mQaSsdUw1inud6ZEbz4Fj308Pjza2Wvun5w0j341npqixrRwbdNeJ6kXmEFd+rQ5SG9uRvVfwVp3TLGkbVgyd6yZzHD08gzvwgMSYXIjsM2UHgH5vHBuL03WEOR7Gbmg5eeBHGgEQJtArfFE5S/KKsNh+k/EAK8nFo91rSf8/jaSJCMdhAJbmhdqIWnmZR/hZTMaMUEmvZm4EsHa3sR4Q9ZG0GdbrjuOFDnU6Da5eULej+caB5L0WM/R8Yy1mkrvCbDJeh7LTgU6rIyew1jVGj+FMfKqrPt6vbjHf4LNicFhPIfJSQsvpJdDIapWt5CPfyooP9HQ7GqGqS44sQLHQ/+6569nbvzW7aRyJmyTfdtNfoQLKJyTlcY7ONkiDWdrmkSSKnRMTUswtZvKlOK30+1tcZUELhJMzVxZNeAAzUf/kSieZ8sg/HChgxJTEy9VKlYPGsNT+iVaFUgcVtnnye5LlmAaMhlPnswntzfd9WpqKK/GQ7zR/v189v6Qf31KnGGKVVnIGhPdCGk1gGy3GnOnmi2XeCzRt9MssvGoLpUfKdM55r0kfhSTPFcgZiIu6NBcQZcpTSa3d5xraTUVYbDKAWxRgZnpMlquR8PRYHjdbXmRV7RovkRj1LFkM2K7w1/eb8LOrYhU7F48F7u8gNUnr73Q+WhpLJdy2XLtwVo0C6P23WcdHI5SKnvuORerciPZiqCulsb5DIAks6xbnQi9Q81r6ndjQQnah7hX9RUxofpUXeH7Jq4nC4r8BQ9I2Zp8GN4dH33a/fWA/BUetaWVw1w8BVtVAhY0cUObXu3qhu0iH8LZCvNBRS8dBFlJGYVEgBnkuRXaJrkd4wSBxxqzt/33Xki9FALZVmpJ1yMTGtGqqbKDLWIQhhlIrF8x1YeYe7dWSxyrKfsqjVbY782CcmN97hwVYTNB5MjlaqvIsnfFVKX0eJ56Hu1V8JHFBK2VpXQH9meRKe1cTrUT27zPkyZymVJTdJMcfJMGFFklACpzRGXl+5CX9cHRXKvoZ/P2bNri50mVjkWsnFlJaaobpzqApITGG5otS3hEmjNJ4lk5lrXY3AAj4IBpAEG6Gb0WGRcuGhj1Iuc4K3e6UV9dGAsskY7SD+7cfVvp1lyNjYF3mMflz4YrErv2AjYybQ9YIMNnBBYXI7OELqAJLzSTFY2QQ5UjZp3P67/ZIRT2EG52YsFJwmTC3k3JAWspXkpMcu1NbCupIJzQ1IowWzwhOG72l51NFzZb+KjsOp6m9TXpXZl/x+hit9O/hamACr9SDtWFmzACUgC7JittnO6bV4uLUDqDBGtxcdMVO+jxu7cAWM6ZRsaaIAX3g4YKkqHi8nH4l6M+ogfoUsLuzf71gzv2qXfZdNGaoOVf9EiyotZjz09ygUmoGbGTmHKvWl5KgZPi+xcHOeZkCOtr9+i9scyAzoC/OLjJGKECscqPfz4++PD2qHlwKq3oyNYFgJYsfk1Cms1NaZLeDS2mxgE1l07LmxCZnQKWbibyTNKHRAznNA+QFGphqH0o/d+qfnoIn+MpzsVNWNqsT2MN0j/dpDWP7siuXZ6JFEwxcWVfpCezbLWntDaTMjXdwJuwqtVrq0Y18QPPVCOm24djupUUiqQwZ2lhoV5krfwSdroZMqTPXvGMYWfGkYH5BqsrBqIhwhtoWSjmV45a/JI0Jyg5rdOwK2KOUw20NgsMFr412AgmI66m1qyYzmleDJhVcQ2cGNBFBwqAc0r16nspd+553iL44fqLf+8s/lFeXGuWQIm1lfWK36FQkMsO4MtKOZe9gS/Lq+oKVAWTwkQoagnT1qykE2ZNOZnco83m4cGHtJtyMBMrbX5qqw55z2ScVqWCQvdzFoI/7xN0opGU7eUtz3IaJHI/z3ZeiDpTT4sYc2XKIeKl0NESHGFT7K5Wb71pWWc8AYg/qdg/WG26UMipzWxpcwjSX5VIUPN5qon7/QndsZ0wzlwz5FY0+8WR8jg2YqTyxuYAE5n0UpTZcrX8L0B6PS1UKfVEhXfEV6AcmKs2RjubVBfg2smbECZwOv1f7z6JWTM51YqIceYQUdqs8PSj0VwpggT2uMWVISG3JFIambir4GjfPYk5h1uzEhHVwnyYy4Za1ZjICY6zE2YzsY7+lex2sYfyXj69UzITyBSHvGlXTIY4xY195krWZyysOLQJ+oaULTVNQ2DUGAMxeMJyEJWrtHc1TENaq4sllxFpm9v57HneW3z9pXSRYz9kLgFMcVmpMPqUlTtvmqA4rzZS3xgeT/RGjVNglODqsjH4fAM538DUJ1rDKSzapZbKcXwCM0+44n3SRGx4CcyMdMxhfaGrmifs3BBICYZpbgWcjT+yLC0xlSs4mulhPN5zzrYJ4vGM0PH/mi/Qv9ZQazzsNjv9OHwFO7DxzgwhYFMVDnZvBHHV7p43lzeDWDzAYS9VDTcDNPX1/JFyYExEl5hHMiUU/8guNnfe7X84mxnyPGUgrStYnmH4EDtgwkE685KEn7C4O81T0cn+2ceTD2cnOx9O3+KLJ2Ao5qlt9+jDh/3ds7OD9/tHHwWoxUz+N7wdwH2YvMJmXYnpDp+0PpAVrywn4ghMqvicxTMfSn6Se4vGg2BogtzGPOyOT/bfHvwmfpk63NFwLPUZ1vEOvg26VsncDnKmy0GTiIpGAdTHxNryq8v1slQnw6lthM2rcfvufX81uaqU4d1OtebOrKQwX+1VCnWLO5VNk8NNJkpM/FOm3DLPz6quaJ0GSyHLuvWvguivCYf89K6LPTGfHqk4wzaEdtKXw0ykauoZNUXNnboQkDLVMR/wcu0fQ1PfQdiHJ4f1TgY2ZHVCVJiCSkuLRi9Y11d+mvOCijgwRdknSomtcNyfEllgFxINtbam1X763KRQ3aTsBxW8sumsPVMD1+yFl7o/gZwoHZ/MChumrUXE+Vx5EYAk28J5FrL/nKmOjIi/pzeTBqowGE8Aa3kuB5/6qtj0DNxQGttMs1wV8EmQjT6hkP6yAXJnpSwJHgq821K5za05FkueeYm97tb67M5nxoyK92h3giyrKkcOZNR71BAYBgK1WPn7Np7h4K0pVVPxLf7fzgmaDvhRx1zTlWVSZmTZ7ODEbW8ZXpezboZzXI1idUD3M097DHU7btJxs47ZkauVf4ze2RX0E9iRl6EQhAZPb4jmwLrmmprXrWSKfdKSBFHuMArdMDDYtPzhghgkikK5TBKKRJzfxuhjurWlalrmnWcORypIUApxnNN9JakyBqqfniLDxp/Npa1RfI02XP+EP6FdoTeZIoqjZZWnZ1JuqxRmILplB1rPJ4UvuUjWxBblHavIATHgXsyK0/FPdjSOkpfZTo5V60bxlzGfg5TRnfZEfCHm5BbFdLhV8LfrXPfDIZtPNmBN/zJUoxYX7qdnzvGmJeT58HGeZD+Gw5lmBGJU7OPJYTG/RV/sw2OQpQTOD3zQOEiXspeBCLNt/emodC9EgjX06JitsI7ZcWtLFcS1e2EN9/9h1XXYCfg1uUOSomO6ez4ghlHet5TdBeyiSlIReYwb4SQpu70Vc87f3lJkBBhYhOo9d8AJ1fFEDmFBmTB9cLXM1uusVtFJ6kC70DrllhmQL5T3G7GFnpr/Wo46ABK+zmIFuTwfN7RtlQ3fhX/GgUGPiH86gKhHbF4lab3D8d7aZAMTtfy+kUbq2SaVJ+oh4PaTdRGp+AZpGoQkVJyWTyI9HW4d8xRXTHg4NmZ8bKg1z3OL8GGMjKS0/GBWaY5mroI4RQr4E794r9BMWCtPMRNylO3ppkCbbndOVnCohw4klAEzaT6fwq29bE3bc+DRJHnfqfABlAY2wXmva1cT0eJyqerxYfoDHE5JRO5xyrUqsjjr3tgDfxgFJ8FfJ+F4Ukq/iTBF7N8vJ5SYbH2dnUaf/DRsNFK6mhH1081FSMVmskVPwGCOE/jp2cm24rs0dXSSPigmmZVuJZxhNWmNICsYLVmtpoThzOZ2YGOnaXtlvUlOBxMOQWttL10Zpl14uRpxQDHZ8traJILoHr87GbQ7hq1zYjzdJE+NOiYZrvB8clLLI/UKUAGIQ3FZiNwpxaGYNR9ZEJl/k088VMqFR1JEcrfUfMPQRgK5gB8FrUol2GhVG+oHTCVcXbUrEp+M/JNwArdxI8opx0sYZs8dkwjOGeM3AY8DR0MXTBY0D1bTnzWXCHusY57kSvl52zabdLMSc7wkQcBppqhR1CeuJiIKPQ15FaX4yXf/x2V8TO67zDbMtpQ94qJHuuQRFzwwLawRWgjyj1SvoVL//KjcvMg32HeuYPnOepwTm6hSfizmHQ6DKWpdwZTt+nbIUnoHGEKBEPDM7TG3k8SLipsx/LJnme7EhiLUKsYtjVJSzU7Czte31yqPEElAGNhUWfmGtrITRwbdS0AFipbg/GVc0ix0bxovqeS3F879MHnuXNManCoMzb/F/8WgazvgNSABQQYBygaAE1Yj6CkdXiKOBQAvI5J3wXQU95sfjs4OdilDNygFdEHP2fS+V7zvb0yZ5NH4SA+ES0dEiEuR2qLDDJKVss6kbG9liRg+OdePHa8gseAxC+LaRAwJk5+e5kCcTucxRV3F8GGdVa56uo5+xgeT44IQR3VGcyD2zSRhk1C5IWNHWu635mUX0qddhfZ3lPs7PazBsK1GbHHHfBrSABS3jVljQk84sAOcx3joNN+KKSnBZ0gcToMMJz+E43lZpzSOhqUuRGGU/AGkPC9ddvol0GC2M4t7p6eHTsEpRXAtuo/YOLbZb+88GN2UvQt56xZvYNWYHr6yPJEutIXRDaPruXkKlzzkIaE7Iz+6bXbaDXlJQgFp+W+yWg1yHhJYQVAxitrN8bArd0h62Shs3YJaF1HpqTzC1lx5BnBzNv4GqFi5owdwCZJTBHRSsa6icn4LqxjIRwzyhJCfcCZm5VgC1JdYPTMkl43vyASukNqY9lvzMvrpsde62w+JWiK+oo4p0FB0M22uWVzLCpatSY0bNZJ6gmfiwCklHab1CUSBVmcunenNiFFRtgQixvZejq+bwN6y6R73AWpB1MPL8CKMLQ78npo0egs0ChrYYN7zQI7neJZ1ODXVxkT3N9KJxL6qtufqhWcVzCm1GOAgIzLmm1K785XgN3Sjv6YMyLuKf8rHkYrwES6IYYKxynJdC3CbDY+IjnhOjOUJunPKVvVZc2f37ODTvhf3Qo8juE+wHFvcduVgoJtTDVGhB/7oxku4PLh7R7sf3+9/OGueHB2duUpb7pZol5fYCJRcr3h6cLbfPNiDSEZFZwa0IvUgH7iOTRUdxr+FcJ4W2fJ09LWLaa0q1ZpKXtc9G/r9qNeh4xcWgABY+RoMYSsU8xIPZXTTiRY3h36HUVicAC+LgCv7JydHJ+uZj33/shtkRmFmHLE/UC9Mj1cEGBZF9nhP8PxHyzrEPCxuJuIHaUqoMJ5jxIN6hisIzkWJjQ07zUbDzrdSB3K+RqUOYwVat+wPjkE8ew9Vusw1VzKP3+FutxOgclcfBzyHYFXKkZj5pWOvjC4nK5jNABtqdhnh0WEaZA+IGoVEeehhUiyvO1LeUHUsbl6OO902x4zJ6k9R5AHjsmR8mL5kckifsyhfOwgJcP6lyGSbYnaAkf48zv8GP/n3wXe6p12jsjlux9Pc5TCxB8gOGBvW6Ucjv9u9vPb0I6vhKlogwlazmsaFr1+9hqBPPAhmzqhUMLLdHwwav7z1W6NweI/68R2Vz9cTGTcWiBIsNbB8ERRzC13/PhyPlpgkyBOHu6DveLAqKLPCYUTbUpSkolazYYxqxiY8usxDUhiYBp2iQmwjUFJBMYkCKzOpyUsjKxjDCqM+oZsiz8j4L51ME/JRzXmyWFAinl5XunA1s2qfr2WZAy+p4CadRzZxQ7/ClZsQqV8rPG7k8jyNjL1M/hEXLZ9OIH+1si0NSZqPetLboWcoeqdhMFnreJ7PWvpMzGKGmHYll/zg84YhruV/w80y3UEtZcV4gKw4cSCsfAa914rCWgGggT6d4CJx2Q1Y/zbPv7y5yMPPEv32tCRh8yvQE1xQqm1IP2x5h0qqi9T/VcEhKZWvev+cZwsMjq3xyhOmcJpeAvH41xjlnMlbS3iU2xuXjSYA1/nxjLju1eXKk1M/tcxqtVUYW0/z+KTHKk2a1Occ8qvEYE9y/ECYePRQe+KYXCfHJLH/tp8aoDEQlaeEw07J1vQS3tex95MtzxKnqqt9abSrAr04hUGkyrgII6LeZsAEJnpJ6WZjs09WQL4DSGeZitAuGSixfSPGXMdNODTFMvtDw3zynD/DUZrIZqLpolwuo/rdwY1/GYxi+mqdr0Jc9goEehs5Rc3lZQb1zkBGrMdY+jZRyUfryxRCANRqtmxuJlxjIrOdJSWlZY1vG1Inf3RKFoJ4toziDM1LKomuYAB1kWUyWbM97jEZBLxwvgOt+86WEy3TbHQTdCms+zt+DGCTf6cEDVJZ9izPWy1OwcZrEMA5aODVagblnX2uU1Xno94AF+hLWn0MtRx1Fg9gcLJMeMknvHHmy0doGSTeJCa7QaVIK+yi+yJpg39oXy05oHphV7thk9V6enD0oZh3hfWZZ0jAWhCXu1plo2yDvmTUdTfsX3Wujwbm5kk7CWZI0pxG9ubkMaS+fnvcZyPe8bsTM9NoZBohvuuMSns7kuqwT8PWIR4hhav3Bz2IfibmioxzvzESmyTapERls7PtD6NwWnosayKZZ7APE13drTz3JPYCAblh7WxLZYPrFYXaiNFLV5CdFQonW0kX+DwDHrCY55aL1rBVq0oVpsd11+qndR3GU+OyXsEDbkErmYvJVVmhGNCOKITBRtxf6I3QkS802WB7uc0yHJYLrWajzETPVrkh3H+y7o/QklJOsik4+b15enZy8OEd6CbRjPvI/ofvCDU0KqwuWMeq/nN2o4KF2Zd6A81a8HWpAWfsQmsZ/vLDI+Oi2m3xbrCIOZqQSC/67V6nTyq7DdJslEEKfuQzggcBeLLMgOk2Yc8/F+Ab2S3ufA3cAuluwM/LERKKWEPk15KOxM3+9XwDI87iCdnM4jaZhcwU/tdUIkdq1nR58yLAJwUTfZuvCt+tRObRE7/fDnsfxmDX4VkDKbOsvmJ+De4j0QZuT+XMcdnpt9OAYzBHCfJci/JbTCCGchOE/ji5QgVuzVxA/rB10/kaNDXDQhxfK/g2GvqtUXoRzQddM7QWMT/Ro0ZYj36VmgwuISOyeBw8+O/OwNM12X90BjvUyyQhhsKQZ3E0jrw0PBpdPLP4fKSCaUFtesAaoOt6RUYhHWWAMF4GVchLYFq6GfW6qKwAjxP8UpLfLsP2PX6JRvfoEhDLlAUBHqjkEPdTNS0Dv3Urvrs/exYvB7tBCbHAK2XdD0ckpXmQQG2gI89tza/YUXoVg/FGmOil1aV/HkLUHhX7/FaTihfR4lOi6PXa4Lfg01Oa2J7M+k+rLQWkI/ZUon2ldHz0UkjpVJcqOR1vRp1RN9isl+uZD+Eo85axE+03Jbr45qYSv8GuzMKDIWJ3rbz0os7PUzBqiZxVzN6RsRedhjy7DntApsFnqbdn24PY/4cKJuZJwayWtADD41a5jjJrsDPZuMUqeLv89tO7ytfwdue/SqCiepCfqtg4XHb8DwMVHRm0wxbbHvXlIPIvTUps0QXMo8ZGyO16xWZWMfuAbpemImKGRaMoQTI0zVwh04bA4nj4tJxIHDYY0CgIOz+d6NiGLj1B6qQc65PSI09MV8yVddrmJc6KnZhZ3a/DQZEIwz9zD0uFx2I+HfUvc3bycV/1nNpVofXahaz5MzmskwuZb8ZuKjkJ4bFXiYmBRs20hFnPpqvFdQAec9HWuvR6l+1pqcPqiFyNyLBM3HrYTlaeTMwlVu1U0BpPaFgS6/iRXo3jQYO2IE7byEwJ1nS29BZ45IxJ46xFeu2lZrzY63ixp9K8WjmV6NH7VHnIAYBysPe/aGy/8vJoHaYsczgm24tNOSJ8POk6L6udkFRrTaBmvwCbEYcFtFCVGS0wsbV9XsHwGPNalbck1WJyVRMicRUp+pNPzpewqFFvUBdRVaYcQ7OPGgNXvJXLQ9xJPcI5lKy7S3tv8Yzx2xAAOGKCTQk4dXjn1g04e44ad0wiC++ixUp1qeIaWpIKjXuiKY04wKotEcZx1mX71/WKf4Zsz2Qdp4CUWWlZ2H9Fl9ELVwYIayNPqS8qnCwaBM2R6qJcfiK10x/NcjJKB7aUy7USuQQdjN2LeYclqCSfJVRa18mBJatcV7QzNDFN6B7jYrxAhlIEN5xBGI2cDM8i3HB64+6oM/CHIwwmWMRgos03nf5gPMpQCRhdB8Qz9NDKbWCd4a278YiLmo8raalR9eklbS5qHN14rAp/y2JDetekDJWMzINPUpsiYqu+cp9BHOaBjnPSsGNeWoGqDvQlxICsgLPQXNmXNOi0J1gIvPgBtkF9QeNv2ZbxIcENJrAEp6lUE4/O4fpCWg0M7DsYBUN/pLAX4sFBdjhX/lDTHwy6dqHQmiYqFjVmV0fS0CGyi5EHdoKMggksZpZovC8TitrfBLmjNASCLdKX/O/vJo0smgxqL5NJJYsLJJcmp1pcYOap3asaQYjxXNvU25r+klmuZuepRxkjx6lCHZ1V/wXdT2JCnxd4+cwRnCGS0/QdqfGV5Gbvvvs5L781mShNcRBJkexm8O3IWsU4nnJdKGNgmuVlMdPoXbhc//9nGiU+xp8kvXPEJL/00CPTuPqPwS+T0X9KkumXYPWXEE4R3+RZL5H1vNyW9U22UsnZC9S+rmINlhBFsFquPhEJzsLaEGF/Zt9tLJOXYjuLR/fyKeJZCNbZUbd+4V1myeb63e41A9L+6GY4fqm+YhcqpBappzDzijAk4sviOtV5zbXE1y9xmL90SIdIGEQ83dP0SQAOT2Kl5/Q0iQMY82FGVrCa0OvaMY4sRQhCJPUA1DSYcsBsSU8T7VkvUseLecvpEGffEjHXSZpsV6LO0b24KUyNKmE/MwZbmUdQABYir0XifWFz1nUI/5nE5VkWrdhOfb5Ra4YK7XYty4PTTFs0KwiEWKk+BVBiFrUdX4sz0BtbjdDjeJhmmr3fswB30itiZvullaSXJ3rHYJW6P6sEtaVboDJrFPPItWZIh03lZaToHTeOc96UOonBygVZA3ZJ40W1Qpr70RLC9lUr9TQpdEL0cMO2JZG9wtiv6MaX/v4athnXSvOwM5pBk6KlovHGyAQVRN2e5mIlH1dxzEuVFeFcYgtdMF5F6v2gQKII3gb9uSwysY5kn2e5MoGikSlHAkYk/Sn4ZHFcT1sX4RZ2H6KaZiDhM0o88QftfLc2Jaiwq+nYF6ZP6AzpV2ZMrzX7AWZr1p7qL87eWJCq7EOFL48YbEgg1MuniTKzQtva4uC8FH9LHkLPH427fsuZor5WBHCtAikR6M9Zt92JGFtxT9HFkfSNKXONexr94xT/FaNrg73WTdC63QXnwp+uB2RRKOZFyHAWDHLB5SMbzwW/ex1yyidAAOx3k9VmGhnXHwcywFeoiqqU3WKm0+iFhOrkltTMDRKzzhMgd3GrpScoN0Ks1ZYmuiqilyypVa+GYW+gjN4W9ZnpZWJR2GJtWh32TY6l2gHjOcM0ReiMzJUa0EuYbeuAsnNyYnIVm5oQ7s2iofGMlVKX0PL0RFZ7JPc8XQa2iBgZseQXibmAV8rGXCpzW1PRDoqJSgQyh06VkG1ZXZ7qugjrsvh3Z8DjcHTXRdhnKjy8mB+F49YNH7CYiyOnkIyISngLoG49TPyUTbTMJ11s4EeNth3dvnJ0/S9C3mHUj20wgUCX2Leix6orBYZgMmfIRKQY5JRjgvqzEkdrQwaJrZ8a2NG9GSTlJFKkKS2LN1/VMqqwpooPKxXWxBp4G4oNpxvbFjdx/7HFcxmiv0QucbBWFBvotgCGCKEVFCBbvCRWybtu8v+JPJxLVUJmQV+iKBh+DYbezGrBIrheFdgAPqamhZygn32e5000vrSI1NONQ2UvBl5iRdvGoSEYt/pyKnV3YtayFHPLBPeklGix5CNxGkodBL5gDQ1/khKiVlfn3yvJo9N0j+GTS/sqFofE28GAmOXlVGu3rOLcLeKGqsJqj+46I32Cn3d4w9y3fDwvXJLU3XVPc1d6jhLbqhG8ZJN7q++gRCToEqLHVc30KbG0HCbvOC2Jh1m6/MSiT3Sy4xg/n3dOPhx8eMdLFcm9chWdpTn9p7Uq6pB8kg7Wu0RYdVW7v6oeaeqguRaaQUry/2R+ruzWOjjgfw9vv1dyigoBMCyOKBfYEJquWn8R96tUBplifXv+4PmVwgBpwV7P7yAnR8BbLHN9CbuazZpWh9Qkdml12xFNZwIzmLutGNOA9Po7vMQ/8g664vGF32Fi2sT/RcPiGYSPxD8VCS1NNdZEmzkUBmnRrYigf29h+JcneSTWHyKEUaft6UCNxQc4BIGmlR+3xEZ/47PPm2Fw1cAEGgsoQbNvm6RdfFPyN99cDjcdncXm7SOWVWWiqDnF6WMe4Pj4s+bR+MQsKoxh6+oIElNajqdQMR+wRJmFw7a98vPEFbXmvpgPpsYUxWUEC3sqjj5kqesT8GvJu9J+OEBjcc7JyghzZog/nsj0EENxSnAzP09TNaQWSPemFyNQL5tKUo+DnOMztZiOGfdYupZ+mkufcaWYt0JL23W+aVOtR/wv1cm7zoAq206ZkVmMfu6bEgbG2ZF6Z9yN9noxGO/J9coNFcsMs50sZUFrSgw7Hz3U7QEEH5t/3bVWIKZ85xHl4q+E2BMkf3ISFsJ+5DCGeM8rspauO1ff/xxcs3/B9fdB//p7pxXmYqoWhHUEKEN9U6dF8D5FJRG3HNQJDG15Jj0nel+zKtkb3rkXebM+42SPIasL13Z9N2IuAwBt1LgB0GFoYRmQkCNm5oU4geLghh1mhs6eqkQkY5MTfYkMvlnoDeLIsh+9IIr8a1jhua15MAtsO2ZWpb2pFv0nsxnat2RSxqwTZlndumxeISCAAGieQNeKD0KGs3vpHvUDIfGpEoseBeXqlpxZbVG88+gYtLqWSEqnp42dxwvanjdWqubYWy6xlzy3pZSbEe5nKykAaXusIC5KJ+PcfOvk57Oz4+ZvRv/18UJ/oxVA3Y9ajBTBsHf9/vWY9kHDQXBaDtacMCuiAlClAZ8GF/g8cBqPQ9TJfhKxQfjSSm3lRa055+5E5GwKh06BduEji7in1aWVRFyNDnrloxoP4zWKD0sYYbWVBLtpjsC+mUJA8IOyieFhEqbbRZI7Jw3anqvtRU2jm6AXNEdBbwAKofHA2oKFfdWSei0RBCvwNepkTuLcMqYNKs5t4REAYLfs0k34/asPyl9Q8z1COik8bOGcHX0b4aGb40cGVJDDCujcQJDVSn3NbnJmAyaQrNlXOUrgrnDXcBx59rHbfhcwx7psBFoc/Vc+HAsTxPmhnfHoyD0sgnMgOidnaq4ItHTNiK5tuPG0RQ3F0MJ4a0il9cLjhqEn9R54WcjWdKfASs9tl0WskB59g04VafV4EyvaENONPEDVZMipEfNFsjlg0R9l/Bb+Ija9zkXhJQrbsqK64rYpPLob8eWYxrZKxxucFfyiZx6f7hzhpvC4Nj16jq9CTB6gA0NniYA0u+F12Lwed5Qcaeyi7a3JnlxXXUmcTLpZMF41hbF3jeRXfOv7ct++gIKPv/6qDnckyTKvnxJZQQWn48teJwEcKPcg0EVKzopSg1I79PxvXLeKSwLwoegG5MlGaqp5XrEWwfXhlFFftFoD8T13CcntYoOsCY9b1BUng5bKhsN/bvKkO+RSQO9G2cctyNJq0mBkgT6ROomNJRtJNopsBHO09OR8pqSEMA+ehNRt850y2k5pxJ4UJ8kRLlPwGdp9mqcNBweJbC7lR8MVq8EDwAQDc/4le6EhLukldRLgQr2IbfVbzLMLbohdhKCjAFS+vWWV3re3Uk+WrIIxzDr/QQJdxcMEA0Z59XhAEfCdTRmleevFvY9SYtik8V57AieQOEAp3ubybhH1FOXH1MAUTht4V9EMtDQxYZGuFnt3ePTTzuEpLgBXlHOlLZenwiMqlp53x0IbecXFhzrxLnEK1daCDy0aMptr5xQ5S33w0xPhPleWTUP7D/Bfg/54CU6cd3cZNaXJ0rJm9I1YJpkz+4pxP6N7XJE8j8l5U5sdyKIjo6PbnYBrYxHzZ0vJYlk1GeeufL6JREimWdRsVaKEI+uWwvZj8lWp23haUgqD9jAMR41JCS1oYkEt3FAjyMhXKwxv4S3wdDXzr+i+HLEsFuIcHPaMLNrSnYMvXzwOIYDUto/JyI9yxVaEivMr2LQtOw660KaaCO3qu8xUOelkz0Ld2PtEE0jJ+Oa0VJXVX4scMYw0qz94bXi4+ogrSx0RtJgms9EpiX25oIYGTCBhW1I7MQkixPuhZHSFIqmp3ygDVm2ET60/6xA6rQSXum2O3fZF3rhCzDFujUd9QkUamSXEDa2UU32TucJwg1ItmL1qbOsECFD/NEYqNmkKlZGaRWmtlow5maIQNNU36HrU8zVV+jStqPfd+z7tKfI8sS4W3cGkbi4eJculLgt6cwk+Kgc8Bj21Cx5AiwDyMAy76zH1ldQBTBC6k0a0J0Xhp0ZnPat+tUM42V+h9DsTV2Cqdg84KtByZqOcmXdQHm1TNXKawzSim66km+CIgZdLPCnDIfEivYJidAh9dG3iCz4LgDm5TWa286UGd8ZX/UzmoVgOInsh0zHaUoYGDU9Vw3c9hS5ZX9Mggq76Ifa4U4zFJJsES0suEzd9IXppZc3QeL6KZ9ITdOVugFxq88+/xsHwPgbmA3tM42HNsnJ8lDx2E0YjMYtSs+9yoiCPcMgc6Qu4XKgT+QUpgMd7JNYoiowVM2U5iHNNJrL1R81RqNJRQgcMCAbH+2EnuvW8yHv9SxB8DSLOjNVJHy2ZIVSN/swW84U5sgvDIBp3xbthbAH6G9L6aHFWRtyKORW3bvS6JPGVVcaNJQQeWkbkJLlisyS3bGk7T3Qa3s9g4hQ5I4aMG6eEumzLK153rmKOfAgPCpyKZCAV+6sBjXNfrCXui5VTaZ6Mh6hKPEFXzZQQT9W/job390ODeBgmmylUhDzqE7tQ/pLb1A5Xu23JLfcSpI/OW8QIrdb0la2fCTbf9TndLmZxU50ltdD8UGFpjKy28OBwXV22ZZTL0lGuZWvJ8YxchFYdvT6ExKgnIlIvK5c6AlKXJC+HyJUVlfWU74Ty48YjAmw+aBwjJ6yQ44l/fVSpvC7kbYsjX1YokjRi52w88kleiin/vX/Acc4aNVAULg/FQHGdz8pj/hIaQAKxrKezHOLRL3GM5MneGHbH5i8W5xLLlta6RykhMHfXx37n21mnFxz60Wi/3RGngKHVpwrfB/3xTiukFWwtRkujqntkpTv50bI4xXj/X8Jdvq1otnk38VCsVtXCRtauUrbaWZNvHNv0k/xVrK7sk8w96RNlH/04nVPHFT8XCftxCcAZ4XkbtVB2tIO9OYiEJ3S3CABZXar++7sU04b+b9qgCEdZq8Q8fQ2XZWt+bJgcG7qs1bvRSzqVT41MmM2IrrG+sdAE3k22vECTVQVj/ZaKM6SzAHTjRfwSjzRMue8tYFqzJOfB1xVlm0woE/5nidxaMnZw9iB87beFJfsXcLrncaX/V0C7edI8sAcBHUbixc1DNNyUmQRYHe6Jrit+23nQ+Ta45j12EBDbzQg7Mt4btid1bTH7VqA/aDyZp/Aj/odO89Rp5FuW9XM6bQPeqQ2ocUBmzvCXIaMJT/OZHOWfS7d1GXuNABNWX9THZEqeyhd8x4nJeQzdF8GMAt86bc8JIyoChBJQBVtnjthqzgsHrEC0SixaDkFHEfFPTEreWyg+gFWHgh8dp5CWd+afZ28mS3BTMsEqhziBhS8nSGS+JKJiYy4czyMmFGIBpJJdu1qpJC6bqiVODZYJdHR5IlolG2GD5pC8Jgib3Z5omoH5s3DxAfJby27CFD6qKuEet9ytCMPzo756l8sVwcZLwU+w3xuaKjDm42JxqkleAvXH+UwlLZcuNsxuAntQXxXRRKS1jWcEKD6sLD+65G8svtPTqJ6GVNaWZCi9YORnQBe3CN7NXxvOMLgaBtGNk+EKVTaKbVR9jIfdBhQkZ1y2ANKSqdxUNg8ZAQCzabGI2SOwoLhPfcI4+Xrl5fpEoPvDTCPzHmyHxatuCJns6ccQkwPB6sp4rzN4VhJflmGPtcPWuAcOWkUOlOO86fSuM9Gw1XCdjJfPdOHDcTc5L/eGOxTO9dbc912+PxybgKv3hRvnOHgyAmH/6X/16SqOcTfk+c6LYt9mHWMikt1aoEaWRYDjHso24fD+oN8OvsERhH+LtEVPAnzx/f51px9kjvrq0k8UwIHCh7q6G/bB++g/D/zYQMr+Yef9PqzZV4vtmUteqZInYzwrtH4V2UwtIrU/RAr/zzfuffF4wL/Zk61Om1GdCo3pChcy36jRJqByrzgKWa/VbGEQlZwpf/HvncU/yotri8VmJi9FfrTFyqmjJlYllkpyb0xcLbhmRYv+nz7r/3UYXncDJsh2/EHHK7bCXgmcdbv+0CtiUrY/I76RtUX9fv9sJwO67kU2cgefGs7J/tuT/dOfnczu0Yez/Q9nDaey8fHksDGZEMQXP73dmnAWp2SrZDz0VIpr2P2eZKY1J3W++c2LsacU1Uh/Vvm5wCvoEQasbEmrs6T1jHYUIh2i5/CrvaPds9+P9xkPoSaJfWG/wRu64fzpO/QIYRMuT5hNbQ1FpFCGlcS/yvXEf8OqMt8NY9BMDa8xm7Z8V/KuJH68egPH1gVCaPIdZs1YIb0mOeuuTDr5Y6nKLEoAp4U5PjXfEE9yM9CgGvXXMJjUMh5v4MD/4gMMWdZfaCRnHEWEZxZrxcP8uw2nOxrCYMh1xb5/63XX5W/+LDofgc+kQc/ZgoR3yxtEMf+fBzRlgY6sufOO7Wg2R3m/FbHj0KCJeY0mLpx/8c7ZS5wfFk4atXLVu6B2l4Wvn63d19PbBbrLWtjpt4dhp42NLUyizawftm6gi1CtPr0bGd6Jnd3d/eOzxwyR0a+sf8U7n1HwOzby3wHQvUMLQ7v1Daclz0YfV+f5h93C0Yl3oUZNnjmW13wlElr0gnbHXwRELLBG5qEa/YSzjDxSmdGAvHXjL47HBTiDvzm4eh+22dOZXthmTD6twGJrc+IZrw8Jo/P7J/snj9Q8NC7FDvZLHY4zvK14vhd1Au97OAiGPklIsbedfEqXbIyKWBKqP3qxLbQLw4GNrf33dKdADMSbkhgfvmHWOOBOfMHoo6NPxjk7wNkxDmc4qxAGpYjrAaYH0Y6w+cshtZ1HxgVbIiQ34MDjMyFay1pHlE+H8Pt8ff6lyOZCbBAYySxbf7ktfL1cPjY8RcxbKTlF3DMnBdknihoFpz+w4f60/+7gA/v7uXyyd8zOenT9/EGuKDhhtTXFSRyuLO+H2Bu9xjeSlyUPqV0Tr+lx3UV87j2uZSAu7QmPtfXH1IDIlcJ/8YMK9AkIenJBb60WCv5mH/sYLvM5HLaPIR8bjSAeeRSxEL2eMlIesRFHA6Ao6F6Rfxt2u+Hd6X3vsNO/jZIr47VOuDRO3EIbObKR18ZVeb5YQpoUX/CIBbe2HFvwmbTljpuroIhQxluo8jXO36458Id+L4L1/uPAvw6aII+xUtRaXQzPE8+FvM9PBNhK7HWs5DM3FwElRs87BReoBCFFZDNI9fPkrX91l9z6ZMdclbXO+sLzvZKULpreoodEIvvt/u/vEG72fXCXo2WD3SItjvHeKNKIVDzWzZw4iwUN0oTvothMUHeFttIf1MCqtG7sTKK1tMbz5hrnx5PldMi/WiyS1K91L6MLcfmkEKf1ao3z8qXSW/QwWjwLegPwWGCVJq7hIwi3BSwG95sDHvf6b+Hmc7lc59+GlRqVRxrL5l5C8C5cDQqgltp/yz5++gk+3jqgAQIekJ5Bbw80LLfCrjITez+0r5acDSqDGVyhzKXWk+na3XOIU6MacHOix/d1s9m8bnrCBEy3MXlEBeKx24EQIkl6HJQuayv120XEl6fCy3zfzNubInSnKMywlLGEW66XEcxkCUI3hI/iDBW2em2ojSogZe+6s7HNRn3cx24pCMQsFcJYHMa6DoPReIhLcbe+vr7fbw3vB1gCcSKWmHDR7kS3zathEDSjgc8TbzHuHMXUrARHzXm5TCETK0sV4VpAcJYBBL1A2CWN1OhbwX3wfoBolkHVyxP1RFiC6ppcaoavulSeUtEaL/pmxISTBRzKoDXGw8fPsDF5U2I3qChMOwD/wZJTNA0dsvWf0KDx+/zcoy8XXKmIEfuQjHDv4GR/9+wI0srvH++c7LCv4tCLNyFtINu6/vdcFHDJ4KQ/Q00tI67MupbrGf7x1LeGwzKvlR7DJO1sk4Dyr0nhsLTER/4QPHHZpcg7X+hT6VU+Pe3gyh93R8IDEWBAXMa2Xbx+C/ns3/u8+BqnBN6CeICnrSuyRoqskXYLxrjdounEmGPojAheywIoDAWBFNVXvnYxEriCPk+3DQf2LBv1YDgijQLGxVYZVbFaW0oekzBfl6gkrAwIZd2miPF25+qqOYa06Ohr53OVOwSmgqEupzwk6HFJJNTG/gZT9I1uwxIADx1QWPPBfctGf1+fJfFPAhDik2gdW8Ynswg4hzO7HV/ZFAXJ+n+412RM6eHRzh7OYLHU7VzehcPbYFiMQiqK88dW9sVjg71Nz5MR8M0Bk/VZpyFlJx/ANd48zgV1/PPpkY6sgeUwim0Zt2w77Pky46b4GSHjSI3AIuP7WdwUKI40pxiLBhnJeyNVWHjit8JxX4Q39kO2+IgRoCWaW5R1VPmqkzh3fHQl+YLXxE8qLygDAhUthDhR4NX9+CjISltUXedLDswKRRD2alXvdVXcRd0CG4mrcBDiOeAV/SHdgrmkUOSZSH6FCH4Gtm9mW4YJzfIwtbfCV7+n8kry/X/883Hz6BS2HZXEE2CJVpkj7FfbWjgWFVvjq7yhbm2ooxDDSyA2Sm4BmxMWkh81J8Jws1Lh56hqNH25rVQ5jbAvYDW5VLrG367RH/eaPb81lAeKvgQwIGCZFTNwY2Y+op1uxaEDmreKQdowWF4MimbGKUSP7K4jj2n0ksdt4Xe6RIn0KiE6lK3+QsZ2Q6xOdGgHjXKH8WoUsVkcFvtOgRM45z8VYNb/U3MK8DXw2/AVlbuM32DXquIauw2M2H+IfUOX8jpkUFTOrEg4kytgW7nQ0qO4qPB8CAfoVMboe4k4AXSlXllZd5RrwuRk37NvDnKpZlX37j/iubC4SefDW3JAhfVJBat8Yf7x7lPv998+Re23a5VW9dPV758HN8HuztrBzyf37c8fqTCymzXjHJAck8jC6XnIsbL+wjfGxZFoxjcCzw2vWd5lTfSFMcXsNansEufcVGhBHvaLCDGkQsu8QpPpvBZfLnHYiEShs+YyMrsUqITyd7Ex6yZwg/dsce602y6XmNCtcsno4etvcIZjTg3Gx8ERm2MHTjgeNdiZA2B07GanUWb7qENVrHFNr4lXKyiTh0G3lUcPmKLfXl9FYesWMn3gs+SFiCRXBTgIOYHJSz+FIy4oUM5onvBUD0gVAe3e3WsKZ4cvcDZECAziZcEZZ7aF5/Y7rVtKIBsBOAj0vFYl0AovIiq0VuXc1ZtRZ9QNNj/5J+z/YLA5DQDBOxgyHhXvUPEaZ7qnyU2dVtj/6mXd68tbt+COR1eLq6XSwbsPRyf7VBE5dteNmULI/yYPV81v8bM202hkwGfEy+n3oWlxGMuML7kNOLw6V5B2BaZ1cBP2Men7gu/7mUYG0VH4BKBOweYGpObgbaVbw/HLPCQ5OlZthi2fy067HfRfuRuZx4zYU+hjhKBZN72wnSaQsArYQvSFfwUjREw4LkG96NIl+E7eXaSklBIzqwkp7tXVlVskQIWCexMC9EFus5wJhxlRCot4sgw6z1KdJP2zSr/6w2Z73BvMevxwX1VWin+jYvwHDR/3rmQbDTIQNzLhJUXZdQO/j9JkBtYOTIraPmtCtEK24S7oMsrLWOcR+zFcWvEiKdquoD9LvRKDiM8yAueV6zX2sbQMH1X+s1JfoseE3M9kA1BzZN2dw5P9nb3fmycfPzRhq7F3YMfaRhGpHz1T5YfYRjKkDVbLCiBXi70KshJ3yivgRO8cH4OK8vvh0e6vzX3ARHjsXFG9NV6vQXlFamxHHD/yfIt7FmJIbI4IusbarKAHxyoSsMxc5ELm08I1zyjGgrwCywf/5h6oDWQ7K9a8wej1zl7g7hp86VAVtg5Za2gzsJOnnSfd3AYTF5QjLs05JnVBiVTWM+xRcREUsoLeEyjeLHR613s+2pcbxEEyOR2E2EEF9z+/m5NPrnDNEmLgM5L/9evXBn7iplLriC2jvkOP4CaxRlSTvxTpxEgTdIfhJ+oKkC3jAnrHTCpAFEq/wlkn6gwyL0h/1Qm8C1SxunQcDlFL44mYviHCEEIVZycfOeMsrsCpBZsR0S687M7b5sEH2synsE5Pz9imeE8/D5tnu8cy50d2Wzwa9vvolc8qRV/ma+ATF6PeaLBI9GWFZx8sG5ZnXcTX4v2QSAsxTgpi5YKQv4znUO7awEeECmGDB8ELP54VtO6jarMhxV85OAhoKkQ0LbECjjmfpwzEc3vRa3Wd34DPCbfUBBCo0gLBKp1Tr6pcJmvIEpD3Xv0Q12ApoVOfdrNo+5PTkQzySFg1WoAmeNAAylOGjZrT2Nxm0/GVsVsYygmcdvSVXcWbBZ4ZHnnnYNjxuzxG44FLLitkCzddCcUWxCqgBzz0EE5pUumtoBl8tQwystI6ZISSCdwEwYsv98BuT7jrLQBnwPUj4ADdzlPteOaykd2wOuFNYePlSMLwibFb4XOVAH2bTks1debAb0H4wc/ea5pQomRe7kKKycRdr6C5eCkRTDjhCHD2/ijqK0B0HKjEkrntsqzZXINmRyouKxCNDB5kjYu8Qs9ZIaMoKBVAc7arD9GGPnWJuw/6nhA7m04qvhnAh3JDCij7X3e6RtWP1H6F0/dtvqZdiEyVITbCsTQvFAeuK3uuuWOKNx8u894MwjsvWy0si+1CurUxkiF6usYVCuzeDbo+M+4ksVTYrU4bzEz4lW0i3jTG94NG57zGiBJZWdC2OjnvhUVeBEI6CjlMDFVOWh42JOSCm6FTkv40+DC7fJDL3kXD0K/x4cWyRCNo3yAN5YBHLsLOxWLNOYux8bgx7gs8OgnvsYIGtBoejB2lN2eHbsH1zj8e7zW5S9qimh40HSxJYeM06DOZL7PTD/v3vcw+vHdmfT3z9jBkY30CX08HbBZOdBFkhWxWoBZSaUHBp/MuT76d7OAW7ETG+T0cDzMHx+sZdU1H0DnZf390xni0vb0TRAzL29h8zIFUzGuucitVCvQuC79fuSU4577QQUoFA87pbtZVlsCSl2cbzi0A0F4O89iZqu1GUREjIVOsUEKZ8trsTYJhNgqbnMwX8zPoM4r5RsNNEhSylrGZRsRYtnGPu9cU3Phby++ySfSHv4Rhr+uDnZCewI1YpcRAkTjpiRc1NX0RYN9fiBVSqwmxWAsEgHdyUfvJ1qM0FglWrZjf3pIaCCTUiNNxl58vMxRMsIz4WakJHnpKDE7MxMA4f388ummC+azAzYSFRCm+qSkjx4pOp7M69TQVa0/RPMmIa5rOXF6v3q7Ww/1dSLT+5BuCcQRhV4TosxuZdfwizVHBn1e3fzGi83e0QWcAmi4rZZ2U4+6lJYSScZHSAXvoYnoTthsDBLHIT0gPvPmm0wdpFO/D7s4AlW+IuBc+9yucT9F0960ycHKtJiMSj/YlUYYF4TcR9qoAfyv8b1UMAn8xJF8rMYxbhSM1swIYBpCJsEF7dNOJBoh+GNnAFmWyR3jAnu/RObq6Mpw6O9f9cMgIIeqwLlGwqIhVi6RvDU9JkocpbZxFwZHxihm35MIfWL10OxZuRKFGIswIx2lSgL7xlBagVMhovREHvISL5Me46IBeEN+JUg5UUG9Hk86eAEmG9gijYex7EzBSoB38ASF08kc3vO701S2AnIVfATzOSnbZ+eHDhVHQDZuDTtTDX0LjKTpR4QwE0XcEcmvMaAro9G8dwn+j7A+g/4LnQXNFlVe5R523cDdosh3S1FE2aSVmhL6XUX2xM+MMJ+qRWA3kfeA62knh8tdACl5e4eoHxReQ8o6wUwruT6APYUdN5lWDq+VQ3sqklX979PHDXmp5ajmGFeFNyF+aXN+kYcQhZGImJDFsdjs9cHwox9heOH0qSuO0AHuwS8ce2t7hoGScCdvKo96NP7j8uxUMr9gWD/tXQzaWfw0Hl38NGbtGTyCdg5mxEZWKCSIIiqUKsnLNSmPyyZTbuLvBnTNkAnQbnEU99BZdjP0G03JKPYmmRYw+8CyCleLhPoJTIMB50gtdhV3g7hoZ47iW7Fcxj5FEzctxp9tuomtoMS8HGW8N4Lhs8n0CfFLEaEmDNdvzzqsUn8W+1djKp8ZXBZdsUdTpDiYiOKeQSYJ/GQXH19ctLZgHV3sRUPBIdjBLJ+qiTqEvqwwZAec/YmbHoyvB17KLxK4CI/uZtJ6KmVVZONlSu0MlLmlSINEm9EfnTDmE+tqTpFYX9xznGDLCfptxwluZVEjz7eDHFtupyoVDJW/OaqcQ9azCxduYxhb4BNJlFJwsiHaST77IY5JrDlH7KNYYeVkAytIjZqzAfkzaDJo6vWCo1hktIbz09E1gC7VG6JmHWZvk6pSMdmmDOq5CzxfoxWpcbtcGebcbRmyl7QXo8x78HHaD6KfxaIT2Ehh+jbUgrxAYGBpVtvWgve+ocvjuON8xTxy+cW4j97D0KEo5Bpl3NmZ8nBpd4oYJTT1abJjaLM4L/lj+9vYtvr30nILBkO5laiCW+VH4SOacWZcv1IurlxQRf30SSqloFA6aZHlbQdeVlTj4W76RPS9ebCmHn/PixgVmgNc7ayCVkF4vZ3R8lRt+nI/saFncAfMfJVcaCW9FPFkddnYhkupZuBcOY9eO+u/vf2a8BumfySVmtZLkF+cTAXTu27XsZl7l3d3d7NZXKV6I7MexrQ3oKH5bgaO425Ll1+gm3IDzMpbuWHUIr8s6fLD26i42NPQEbL0SE9l4D/n0neNfmF4R4EsikXblQlem5r18TJ1r6LWEwKZXuIVrpiFybOQLUwo5ToG6X+GaK6VKPYdxoJ1JG7PpkK9eUrVKeNcVmTAzA0tkdsuP04u8ReC3HTL8ACp4FfC06cUHOupwHLCOn73LJLgvxaxOQsp3O2RHZcybWxRGaBpYeeTj+dkO7/rQE8GnA88OzHKPHXYotbl6/E/YGgWjRbaWAr/nSmYXPabI7RKP15/uB6i2eI3mQ0OZhO5TgJFBNuOFuxt/hOcqtwM412HYhguOMAdISz07VkfIA+RUw8vc9TJ+9j6A5aWdfzREcv7+gr5Yykh3PUEGsUJqakW4XhY1h0VGRXQ1k5e5eL3FSjBiTekXVtDzaq0cIybz8AiS6mH3kXIaQMB8OaxxBz0LJ4avVxBCh0tcXE5G9dN9naqio1etZuiEdjF30efjpoibxtmi4hXBBrKKWyD2Cw0pss50idSk8Uj986Jy1welOHSDVKkcoTIrni/EFcO2ZzVjworEEUIdWua4O2YyI2nNioZeBlMa6d4meXQ1geEoalSIziNbYZidDbNOytOkt0nTRPi49ZqNaErNZexFs56rHIG9kte4eO0RWQcFU84rsD/F11sG90QqoiRdVmWEskgDV1ghD7kqxAEcH3x4xyqN/K8UMjAARfaPENQCTW2Hl81o5CNNdMNLBDk+xd9S9YzucRWRtiPDuXEKR2VVnPpXGJsXrL8pRQO/D9dm2w5ygqQZ0NUcu1j7rCYSlhweT/rG44gDfK+sCD9Nubx7l02Uf1BZxUh8JwoXV1eX1hYrDrombP2UOczsZ07Zf/uZPfZ5kPnA/tvPnGTYTVb/3sEnJlSwL+3OVxQ5PE23yVFm6wafGQNKtSsHRyFue5uyLxpf/okeOCn3RT62nKJqxNfxZhV/AhTX5Ty2uIZyPPtCWsOieIrrCtEbcLnGU5IsfPUjrTrGL0eMh47iVbaGfq/t90SlrM6vVBk5nSLgl0oi91SnSgweEaQ8plhAnqvNLV/bSZUE3FdaCRj9pg/idPCN+1IyIsolwVAs81VKnlkhTdbUCX2mUteYP09hsEoWkwQl44acRan75XMpxRhylUQbwHS1+GzTgDZXPgsoU6rRyTdgw/3jo4MkwB3d+P3bzH04dvnSRW9P7gaYEX6AyImAthEVlrkMl8U1XyoH5fFtiCZhhZ0+W+Hh7XjgFdmVzCLySe9/y2iVFB1gouh5sZ46vW+NxQpfNzUhU89trRRjS6w7W4sZ0NDM/uSGl4gYyTj1cj2Dm94RAUgG1Zhd64DurbCbt60efNCa86bFGJNguPnmcnMv7AeMSd3MxBIOMdK9+abEy1HFGGNRXovLkU9fpQbb939CXf/YriFnAk40suRzn9vifOHWhi652igLaZPEDsOIFjAkZam/WSmXmV+y9I20jbktL5f7/nLvltuARfuY28qZL+kZYRJpsnkWs41vxd6TXk+ivKFjKNgfhNECzQ/0Uvx0ph/8VKMflKiZvl8Nw14Tn0pGcKAgZNMCivunYS+gLZsJW2xDBqq04OfQOXuN0bp3B29X13Y2DBkkgXOflZ4yD3o2Jk2fxMWPmPIKGhLSh7shXEjOUcwqOhBB53I149XO4lt0Lqo+5jiYGqb0Ew6VJH2gT/dKPXGitvsRanuHrN2hGWEkzjYmeqER0iuOh53LLobnSC9G9ABHLyqSR3/2W7dBO3N5n/nwbnl17fT2Tkiqb3S6Q4CklEDvatztKiroSKuN2KTUCUgK/2awie4V0Tr+Otv/7WznZH+HcYubiafooZIow+jeAJ/vXwf9G3/Y8SfW0Qv6sLp6nLcv6jXRC9R4MA1/7+MhrB/w48cMAJ+qhoC+JnWa0pGi6DY2weGWMZqwJXKcg0Ln2ayHK+R1KUeeAp4JGgg/CvoAGYFBasopWxTbVFzzbjFuGjp4D3BruI5eeZec7p4cHKvAaPQMNh8S/uFTHypLRtHq3Ua9JrgXLXvEAh13HlfP0ZkmfoEVD01saK/keZfwe7sgCy9ugrC7uIlsKXk1qFsHe0r114ma0XgAvKtwL19Bl/X68nz+bH/8TM+ucg2weuWJ4uN0yVKTxdcoBKhuyVnFrWNCcc8EsQ5svb7fBaNp2MZCTeFEJcoMg+vg26QCKM1x7itmGzBkPejeKkE1gpN6Qa1ZuWA132BxLcszbsOfWR+ZVEzdNdyAVgmTcc3mCl2J8wboq8tWCepadBc/wxsavi+C69YGLUiQkNjZMYS0ILhWs8ldm9PKorONigeRt9uhkacE7fNurBZ6pSrX/+n4jRNdpNziQxVVXVVE9BXeUlQbqlNAvWY9sQraJ3tIaM+MBhg1ldws++6U7gYe6GbZC3ge4iWwqyXPIwx0dlAO/RETjb1SyWE32O3ePaGjd+C3iHJwms3mh6Oz0/3Dt+ybW6AIhy0d6AsUHq9LhCJML0NaVEZ5IbnpGOhfNocMdtHFA4CxxK7wqgN+BL1xMtyFzXEy3CvHAbccJyO8chyLW45DbjgO586HTqbT1n4xas/6Oo/RA/h8oZOB04xC7sx86ljhNuZk1WN+gOWnYA7hXiLptqUMv0++MasUFQEgq3wxsj3+AB8EE4SnFXoyS49YbR94Ems24Q4e6WnDLVVzr9i+Q8cS+Yw7ImeafshJH3HqL9rZqiKC1uRdDRfS6YOeE86qq+UV4aBJhopmyKF1sjun7Kmz5uedkw8HH94VylqnGu45Y8WIJ7tgTDDsA1Br3wTf2MZAbRyWMkyHrmkN0ff1qnBhTpAqlSETNM1AFdAQw78nWIpsCdCdXjO+8XWObTzBVCQIk5HeYbUssH2nu6Kg3J+MMzQNBe2gfy9spOBXCBQPQluwMYyzQOE9rRF9sTkUBejErysPKcXkTHp2XkVBzPLB49i6QV8XhnC71nj48CrFcGCg+AKSwAYPsRGLRvfV8HRIf13eFSU0uwKnvNrbiHXVa9/QH+wd5r91qS8iUJIWhIcroiTWLuaU3cg91MpkaFkl7MOVZBJCQBxkdFw3lOKzNLF+t0sqQEykpeyM+moT7t4lbowp4XtJR1c94WheYXcbacdyTC7iFEd7Qi3fiozOTPR+Aq3Svxm0ykKootcGrdI6Rx3AWJGqjuLBD5ZzgfbhApqS2A/dcNhgKwyQeNRl8SQb0CZgrjYw2orqR527NaiLhxzwNMHacon5NOQkx5Q1iSu5svBf1JqWkyaxGDj9QnxouRC0BSzSprJl8wqagpUaQ5Fnj7qYm/k/EQrMcVZHdS5N9ULdRKabGHYrJclyTwktA3Nuy0aztjbkUUc1r/HpjPlciC3mBO2wFbSb9eUg8i8dGa0gcjbFfDA0hREKbKsUsQLh9e5GgjK4V9dBM7i8rtRcFQbBZ9nwyUvelovA0oFEd+QBiPErCNu10Gw22AlW9aNWp4N0Uk5HsQG3BTErNoSCwoVVAEWLifOtKCYKw1xA5/MoXJGg09uaGJnNOs53ZRcGHx4nB44HOCcXvJqaULQnfMVUFHo+xuhoDhH+JcRz8l0jMroXY5pTVFTbXXplOcZpFVSNMho0rpjF84E8KyYpZz0TieiB3hVhDmrLCWf73Kzqaj4WonMZ9fhcpyAGYtFIbj3Np59C0tddXB2qF/Sb8dSBD4oIQYAZq5/xI9Fb7tJRBxetJTFSmvW0rqlhq8qok/GqWuGgz+awO45uFCeJAUoQfffI/kf6zb8aDQdc0xfZ/0c3weIoiEaL4dViOwSPJ1DegdN6w9k7Ojr5vPP7wenno5Nfzw7ODvepRtRmrKwJqx6ucB3tQ267h2dwItsqcoT7Jcy1GCTBiKWNpzdYEUFCiurbX+HBWgnrkSuERSMAS15Uxw/lqlvF2KgV49gWzAlPMqQdMA3tQta48p1TwXZeTC86oTH6/da/DShqCzhGyNJ5fLSLmFSrNZGHcjAMr0aDNlhXBEDceXxARWZAGliEMdOCdoQ8VauI2Os4SIOWqOUJvKfiABkzQUCFSW7BUxHa1BnlQp/MrJ032Gn4f9G4sx07M/RosEb+QiS3oFnEICiAZdgIxkOhbv7G+tQMonFz1B37V0GbYH9WCS6QgIxsqSX1gPRY6hSuIkPJFD2EjLBzlQ08n1af/saoNKYeISnADolMrkK8MGgd3STjt+bRxq9SVcvJcE5W4ECcOr5QCbM3WWT/BN/DV88KD+fkimZ2Y88f3mZOwQvMA9Rh4X0NmBRDRgJHLfAcoYfRp2AZ0ZmUR6MrFSrHJ6iedQoAWg8Mi/RPTBSh+tY4gfQWdskTqtm7bFwHIwAbPQYnA/byJ0EvZASAjcVXtsGKjgBPzoK/yHc2AuzMAJMu1ohBKxRidxdcXTVb3Y4Cm0GHn/zZZ3Zjl65LUo1xJnVkfUH3wk4OVDiBwg4NQHfBJSLGsgMXvRXwpB526Vk0PgBuHdiUdBFLjpC3QKyC4ED7ntUhxA7WNWPY099VS6yTfD8BUdPk8AaoS+v43abw2GPS2w+M5PxA4JmAt9IML6/GEThYNxHXhiqirWWCCUEiPRilCNFx0FAP2tthcBUMCfSWkxdG4689A9MBrYta4SZlgkcpQOF4esU/B973e/8mDNXPS9Zt6hMFAi9Llg2ZIGExgz0IEKvFUk5h3xajcTQIWqNA03/Bx1DEQ01/qGAr4+hjLo2sTHT2QZnN1m0zYiMJv8bDTkKY+U/0n0jc/0/bK37rddWa4Srgj2jaIplxgfGWJSVwRmxOBScNVYiqroM+a60pMgXoTaaVheCpJqgi/ZGlA/R6K8K9VoPdaOKWEX7dnoG8EYYjCjCjPlBRuKpkxdGgqxfRH2Ib/3T/9LQp1BPQg1URoXbxKKEc4HCxQDl43jeg7PgJoA78d5H+LlYmIjzA7D6KGAfivATuw2p9TYQgl0rQN3Zi6VAObEyGwV9jxuYBIEdTaP7BQKmGBgZfQH6yncdDuDEEGuhAW3Lvqglse0k6NmnNAX+x32/vEqQQmbgG0lsGHGWmwD4MFHjGKB6oJCDq6OxxCi7EuLHxRaZspBvj5E/JpA10jm0kdgmBh1K6pwqbl+K4ddVh5w4UQlwyCGmFsB9Qr8MBxf4gHqxYZJ0eHBRFsuhSGbzPVnOnD0Q7gjACfhF+YwAVf0Bch/UeVdhF6lNVBM1p4zpgvP1Hrn2PtJWt5f8SyvlTdmqOo5/9frvLSVxb4fEw8otukEcAtLe7s/vzfvPjMWCF7p80936Sw1LjLjp2rU2SiMbDqXEpCTAAHsSIFaMFY2kpgVcXU4JwnoO/JA8AZYRe6rBUAbQSkWacDTqFmsdqNMLO1ZPryTNQZ4Ee6fxLxz1FThdv8wU7EbZSVyWLYaajwzRO4VGEZmDyVrsKJKy1ExsRj6eoY3QSDj6n5GVnOLW8XCnqoPMZVa7ClVYxygftnHMkYDQFB+IHnBGnOZa0iLqLiuBfWQeK+ePdwz8OIJHDzl4Tg1Gbpwd/kOiJEUJC9DQ6luiV6A7rnWRW5ulUHh3kM1A2E97698pnhvj0CuQ118ULfk16CiXK0RsIzF0Nj4C2yYYEdfy2vERlUTeHYHVsGURjcCqEjnnFgHFEgwCDJvzhtemmYESBuBSLqeNqECb8x5MDjsy4uizEQwyeBKrwU9i+b7wLRvCd88TQBrsLB78CaZFlNfJMVZI92jDyNNK9Cwy9oQn8+CZmiYBrluifc7h8wTcIadei19xzQtyncChM9qh2toYkwI3dj+r0kGriZQEfLTxjfj5eJEVc8f2+7hWzSvDBQjkyi+tURtdV2hyn9HeHm+WUv15Wf2EIUM69ebPK2srr16uabqQWq6GyLLS7jlLWxkYfrgozFP9pCdWN91jRJxqlulK7M85E40Ndnh2B+5LTLXZ0brHvDTiYoT9iVMDLCgvA+fwjW1+DBh6k7ISAH3ARhLIGudv+2IFwqc7gxyF+GQbAmzEZZPDj2Ge/x/6PkHwOySHfrBiDVK0s2cFG0vIK57e880XvIgN4bftnmf2TkyO28xCO1LtYzzzwaNVz5CgvHjNscYprj+wx/p1R4kf61iCAcKG9w0uNBodNe1AX2Q88as14VrMOfoTy8HCi9stE7bmH8fHhztnbo5P3Hjf5fT4SyW0kbIWOc7nA0QpQwL4bLPIl4HKboeQPPO6NlPog+ka4XL20rNBnGQd5xQad89GYorTqFVc42eV3mWQM7CvehUs98lkrDu7ETCKXDrK18MHkoPIuelW6WiJdcYN7ZtpuyZdUtxRkhCc8pX8a+l/DV7qvJXCOPPDt6Oi9STcIP5CO3GxaJ1EHmuifflV1zQCyMILGYx1LuHi/hdFrZ0ZhJgr67Qz5nRYdxR+slIU/278xmtMHD+PKgJv8Av6rbGVjYM1WFvQywBZub01O9EyVAI1fXTXUdTPYlaCHJcwa9e7DR3Y6v9v/sH+ycwhQTB9/OjzYZV/Y5/6HU+JgVmTmvRZlJwLXsPGAseYBfOPsqOJuklF6/IZ0BaAxS6Chza60MUGZErobxaZBiaNf4ZM2FUaB1etqyGoKapQxBB093NgRBaTWQn7RLMwa31SLa0s9AsDRBAZZjt42GA77oVxC7BdpceRPjeDg7y4l65F0TRMegImIqfz5sLtuvAURVyVUqqqY5t4D7wJucWS8vUGhjJgUV7yFmz4C2oVs/L5EBsqC5e07kzSur4NhjlpKFoee7lMKJTqYlKoIA/FgAyi3C1za3MemRO+mtWytPNk501VxRcJHZS0m9y8uJHkFfburDNUaD2lqNHnxJVYahH+twnM0vecApwJq4C8okJq1PCL5re3Y6MZ/w3pnDTkXD0sYR4v7RFrmMcINHLWeWGfFqFPWiqfBqqbgzLDlVcX0WUI6hcH+Eb+L0YN/BW/h75F/CSUbqA/5m2gpPtJwXY1v1m0Ajh9pnuLKU8XFQty4ynj+UFo9pAiuFYbbroSMW8WQN8KjuhswaQfzh8KzjBtsjoJhryn1nAhddBsFUZMrKQriYl/kOgW/SAB2ZG1gyP24T1VK9TlGp9Wr060KJjT8KkZ6rcWzsEprC1JHUPch4bPdBd+WtJvCJ0ZRTQzooigBfgCJydPaVxj1zVHIQ5wzjQwf9Iznud4PO9Gtx5b5618CxslGVDdQZGAivKLYDBVYcrmHZbbI2PmC8RU7i2/9xatEfAWeP8R/rS4JlpAtoI6YNopV/qMz2Bm2bjpfuc5HgRlj2cVNGFjPQFY3jysNSaJEJ59XZA/q9A/rCb6Nhn5rdBZSlyTdQFkiGnQ7mCOixH2xC4uVAuNT3zVPjw8Pzpofjpr774/PfpcyiMpzwXNcNLkAoIufj3EBh5omJyHlMVaNU+aqThCnq0YiSp9oPizPXbS7GRyLWVDm99WYN4/0wBjHU1+j7IqoEaMFRQzK59Mj0XRVbnaCRiZNAEbn1GIx5zvdK795PAxHjH1r4l4SioM16d1oUnIzr7JMNKUVwevfOkqfZLxT7FyIP5g4NqaqpuJcDx8ELR20HHx6MYxzXZ1P/5XSiErgrBohuQgjiMV2AJKMcOGJIeHjJEfnX+0SeBRM6hENF2pHlmwuvdtb18GodZes4595C/zYbt2Au9PL1GhdcPa3orGocU2RCJvKgy9G/nRw0+l/M4QWjJ/Soq2yrWO/H0Ay9NzW2Xh4CTrIt+GQa9Qo8KlS072kSiU62xknxLV0i2f3g2AdczMDB7CR4Yr4Bqb5AHe53BYNyvlRuXmRb2T5O39HjxIKwNZuI6Gk9iknJ5wsjJgswj/ImEb3RMox0Gg0RzfD8O76Bn3JomL+cjzs3t9hiCIURXYJXBB+eFUaR8PSZadfGgRgdcovwunSu0eb0zGPfGokPDjEwQq81gadVhg1tErOCFLmi+lX1XanymZW50Bb0MpaWUQbCqjdy8smWq+qjOFj0hkgnL7mMWKnJ7u8URf4GZqRP/2vPqUw36A2ClQvJa5bm+gQz30+xDCcCxWnhmx/wbreNrlLKdPF4wxgtVuqwLCs6LXwFE6th/qNu76yohPJVzg2QtkpZCG5rYCpE9ogtV9B4OVj+pqPKe8TUKDB+LLbgVy94AWCX+xiAzawMfcDxfyECaL3JNjMZULHx+0PBkRlnAX0Ilguw/sB2SEsua5EgjFaw49SaJSJxzxdzn2khus8AoobJISuZRSCmfMm6LE/PUQzxrRcOU/PTrOufafakICAp5hmK4ydrNpExqiyVlDTDcTHlRjEdtjt3jcHCGmTpJBrGNqyrCVXIeZkcRFOlj6EUeUfhV96dr+5c3jofdmHGKmD3X3k5rgx44FqI4tQ0vnryWQ/djr1m4Zg75CO86pzLV0tChNGCObVArREXcdce1WgKOaBFa/Kegah3wKk2KDw1vj5is4yZ6G1UuhwUglmbTqxY6Fus8V4zZb+0+uip2Kdp/7uBSjmgbZ/Mfhr3PnqGYwjHyrzImggUA0IfYAzk//2fgCfPfAb4jdL+l2tNZRGoMrb4B5OlyjelKop3l68hnZAlAJcSqdXggPAk64s0QDEu4jcOlu2f1Qqq01xk5z3FJsqgsHV+KYsYG9r0xwI6gHytcu20BeOQ9Xq/oHi3oSVqPaGur/IX4SLbMZqjGdgwT3R7shFl/p6slLQZB30r+RiNrhUuzSU2oQpaGzxcalKkTw2LBLRB4bZ+w46poR/nOKaiLqTV0YuT8uewo3QhoRrIUXrJY8vDoKjOXdCnsA2Aa4i85KdqYrvjKwS5ceQoVo9LWRIzbCuqarrEu2zrxS8OBugrdlcyoed9Z6hpRko6CwPplPEWOf5RCPCNCC2ZXkx5Jq+GBwU+sCyCknZIu6R4l8qw82Vmn4WzXHGJVm5i9TBUruUixeCjwOH2FLFK5YzAAL0IRxl3kJQvqv3Nl2q1/emiIWwjbIf2XtF5z2Ghy0tLelc59PP+oZ2usjMUS9SGRQSjk9/RuAA0NdP2ijoXp0FkTlUahDJw+9lX0/OamJPYf/inMBT24Q1pRPojckD4XeDb+NIYoxMYjetK2lS1XKv0MpBThETuQMLeXp6cPQBxL/OoMn126USHlILh0fvTj0RQHAuT6a2yGXr/r7YW2xLkcyWe5APixb9ySvFmiDp8v7RIb+nJyOMpHiFIX91CAG7EvrXbam3fplpeu7Tk6gnXlCHfhrjYCzM7atWN4wmcKNQC89uV7OXKpp9hZ/KY+TZg2Zbi1wXRnOG+tNlwz2NJ5B9wbbtm5gG23pmTrhlniepp67JX/y7L4eTiHsxs/NhL+P90BQbzSsie5s5PPgVjetrGGxag+BhQDmev1dNvmKTapFI15I2m8c7pxAUt6fZM6yTYgwv0IkehzC22kQKtkLCiJLyzBR2SUIHWHfL1HeeaVDMJZEMKKWpwURVpudmL2imujfMwNRphIMnME15tFyv1/XO6l6n0kzhPepf9HMmhW41zI2hehNz3jCVYZNeg/dLDIvhUTeRJiZOxZQ3pJmoik3C5YiySSqU3V2kc2yC13n6CjKvpPOV5jqh9KFzVIp1gDw4+lSp3kS/3DfF06Zkoa/RnNiDzeimczV/c9b1YCFR9ipgQHud1jDU93OcN+LV09QQNMW6c3nfHO4P9odHt5D6rD8iMZUipZfjlmpjw7/R/iG/ATqRn/bfHXxgfz+XhS8fvwGlDq7eh+0xagnYJmoOA8ofzglvyxM6lhO6sd+/Jr+Zo75++SfyZirp13ZDNB79R4yZ8D0WCGri7V8tXj3tsbb+2MlYqUx4eB7/xYcKJulQTq/UFWnvvyluECv2ORy2j0HDT6MvbeIQS9MZwgPN5t7BCRFjk/OwEmPSsex22QLwjoGVi9qetzNQ+pYkGRc6kOHYpkqlPI+QsYyvyScLCh6lAJz/yEy1mT16JuV8ugyT2FuSYJrJBePlns/i6vuWWgXSUlsul2PzQMmrTaH0Lr++7mkgh+qrFMZfc8lfOwdACJ3wJCuf9mQKF0KNsdKvueRvZxHJyJS9yKfzElPLWJsyHOzNRa2/o7Fu5n6GZgElpooxC5YTOC4Sz3Zupz6VGKao5fc1db5Fo/Mk7Ye5nchw3kxvBz92SKJMNPKKsNfMJ+Yq/KxRo9lCc4ABxEWGICYcs899IbIhlAEPCvhMGWe4CP1Lx3/fEb93wx6ePa9LcXwc8U4xYZTnXkx0lDA99ZJK2qEAcsloWnWYqHqmQPNEMag7zsDHmogHjMB1iCjgmmqEcqiCHZ6AB9NPDk8/c96HlzA5ewE48fCikzqZ3HediOowWpTNzlvXmX/ZDWzKL3pJdOdeNpZGqZEvlfgXjP/J7934feBL8Yd2N1YM0mDDjP0E62hn+Cc7SOmJRiPtkR0Y1wO2iX34gui/Q/mQ5TGSCneim6+d/mK1vLxWOmqN2JcKeFlpT3jgTwNvDSmouFQGMRHC2cE2fzEW/lm3sQfv/e6dj8zLKWfzZnhIXfoJbR8emGpbfGS1TT65Kt2lLWb1MaKBeZEZTZQxCVhsFIyeXXpR74Q8HT4PT/b3YA++PzkDk3bz7GTn7duDXeprTURvp2IS2olYYrzh3P0TEzZOOuzh3ld/SG1jJO6qZo6Pa/1jtg4PQ9OT6TISnZtIE6gozHx51mcsHZl49kgdDdBbc7GgzmDch3jriaUlQ0JDtSSClmfVDjgSjEG0OkWzNnPFfjT49uSa7eVnJyU0GogAU6lK2SPVZ9PqawnvVfFsqoJztT5MiSLBj8bxV60kIladVVE9caFZn6ik9oyrK2cagOmlTPv/dLW7Va1Qo7RCK7oB2OSnG9szaJzMR3RqOYu+J7VpI0ZwwnpGe4tafiKfIyvHo1Q8GabyELuUsH7GyvNhIiit1XXnSrexJGQuYdo1RB1z4K+kDsUqlQ79OwXUOMuqNc+4Wcwk2wJCWhSLyyH4ypRem73x0a/s2i5+nn78FaxjdB+1tvrBtO3igHMQMuPbt1qDHqryOAyuAshKgZZHVAuErcZa6YKxVA73UEN4oGptBZCduOee9OWLoXanDewsWmPr4krI2DC1DV3ITpFln9MVTXaty2QKWnxbxJgh9u2UIwAu8N/4LBe9eF4i825O76oAQpG3N+SCR8gimKhddGgDDufd0L+8RLdl4JcZJxz2gYEewr2zwO/Rc8s8ysDg0LLux59/+dp69+m+/fPt9WX19+uPvU9V/7cPg/bn8vj36trI5fOM7sLVGpNhOgSxMgovx1cFSnPC/wwg1wF+wzyTWqIUlbCskcEokIyXddfX13nGLUa//KFKzIV5uXiwiOt53nf4hzgx0KZEHAB5PENd8YH14WI4T6sGgy36Cl2irPL0HSLLWVdEE9suvy7suIgPVFVYZ3te8cQrnrLx3Ptb9wdfQwyfOngyUt+5C3basZx6w0scP0kBN+1X2mH771Y3i3vRpA4kz+P5r0yxrZlSty3EJXZ0QzGcZoRLArkkWvfarPTSI1saQged0TXwxRackjG1e/6oT9VUOI7IZMpMZQlJqC43HC1tWP9iwHDFSggvnjFQ/OYbjsfPssXuKcc4PhS4AeUDtAcj6cuAOEIVCBAxPVsM6BaZK5NnW/L0sw+xAyStm15ebls+NRANwbiazqjDMe7wg3LFY3HqJ3pcMwb/+GYAgXs7gEkAseToqgroEA7H/cNUl+3OsMGGH3yN3+1D/CO7wA4MJoHSjkZcn2qtZvoqiYiEBnWcUu7qh5MmsCbOKYMzmbjtNLNiagDRFDYlViP2mGAnUqun98ZYkVV9ceI0ZK0TwQcPRiO674FMxs47xonGJ5RL9x4Ecl4KEC74Q7k4o9eUxAKxci5DlI4od8Uw6DJ24ism+GaH4Zhdug/Q9RdyWYjyTVkMXwHPKADfEsGkd3mZ9Akg6QDjjOfNsKTNAG99yrEBKTY2RRfz2CHkNfL4KGwpdRcvsc2HMrUsK14V/xkVEUgdPQYaB/ad3k+mK+WRA9s8XCkrR7HEV6hIOtzzb4ObDmZRITR3t5BxL/3WLXe34XDrA3b/zWBT+/V7OB5mDo7X+SWoh+dGFSht2M6aAEf0Fnb2oE5PV0/67cO9nWMuL2RFEYgAZfSK7dCPPOEMJp45d8dcfcZxY8kSxIF5nZ0WTCK7tNcZsovh8N4pVHlOJwllxOnSskhfrBAnuLD7ltFD0Py896864R9hmYqj+3Td5ic8CQJHoWwgwya9ODG0CDCdNN9Q3d8YLhe0e6Cyvub0Ei63OxGoUSVEQWRG6SRJIcBHId24u0Y15CKEg4I05qbkJ3PNPAJi1LQ8Z3E2egGBxvcOTvZ3z45Ofm+e7h/vnOywrzj+IqcWAlVaCnlFV9FXtgLLy/V6MnHEFQ8wnrEaQcyGjnwBFDSW5N7e9YftTg+UvfmdKGT/u6FilGrBoGOzqb5SUsYmC05T2sx522YcS1Uj2VxXzCIWDZLVwYiJAHEPu6kO2A05GMiB28U7y5H44tGiKfLgs8KHEsq2/4P6b3OhfEZtMUXGbKrI/y291xRpXpr0n741Eioei2BEEOdx48gkccdu7lim/Fa1NNs31kFxayUBtuwVO/2WBhjsAWKebBAxhed/YpbHqMfou8JkklNGqy8xFeJbEjDe+30mbWDGSQL9ovLkY7HOM4bhVvKAM0L+CPPMwDdIVXDw4R09spowMT9/I9pAA+hjAQI0MeROI4xPdqu3tbNRzOvoYO9Fe3REvycx7TQmvfHLgNMYv/aztPTktIlBPYTKfvrB/9pp+aMMRH9kzsaMHexmIHQhGBrqC8IEK4OSGT2wIjLkof8Voq+wf92w5XebqDFRgW90cUCH5KZ4fQzeNmzc63o8N3dBpZYpKzkTLpHBcaCzJcbwlihlJpXBvCyM/9wQkcanPcax34MbOZCgwbDz1UdRSIsaxg1012GtdgZUCzAO9bIcmnf+IanGvt3UDgHy6yfGMbfL5djIYKLrWjJjkpcCE4ONT0h6QFzMypLozKvFRe8Hpe6FbjccfQQ8CK/lncH4mTUKKpZpXEDGFWlaYO1pSg0X8wsy/r4okw1SRSvCaNnGFB2IJrVYL5cXf9rZW+Sr2ZVJS2ASU5PYcCY+UUwhC0FBLEdtrwqFhs3pldETJoIRAJY0Pb8YiAZ1gHR1FZGGNprJVztdCxyLqH2xsAwLF8jkS8JFI7Pnz8fNo1NPub3A35p4shH3caYQqWdVIXmWmM/2c9457uBtVD3DpJSXlpb057keA/GrQM+tsaeYjqd5Fw5veb/DK6VFG/dHoSKkhEcF2qTu9ek9I5i93xilC9jqHP4cdAfBcH2dyWEHfVZln6PkCQkFIakAx6l3T5SIidWDYdjiRMBB6AwknCV/AJkxEEcDvKTgtRd//XXPoXpQ8VYzcLZfH4Lkshfe9eEcPRUYBgjkxIT5ljLoGWXiF9H1gy7RiWyU4hjlIh1If4wIXGJg6gJRQZ7LyqXWhUx7JLkRIeSZkTlfyDEj4aJEJdMwPlQJuJgFrxpIT3/BhxUToOgYKhJe7TIcCbDtSInM3kI06Gh6AV2ngYBUqyuzvQQ510IV8A3aGPc7f3UIr4Pn8jCYCbEQVjhIzCkTKdkBg3YhWGT501Y46vioED7s9IkmE/zTSvzoZvXB4c3+0PENX5IHOII/LVV0+LSD3iBkzGPxOhx/9YpXMA2gLthptcZBR4dUwwrWKDsy2mQlZhhb4UH/KzGIJ/vvj872mzt7eyc63OPlMLxTc8wfEEwldJzgCnfe7X84058TdqBIpvRh3csjhdoFdxwIGSfX7TXKVlQTyYTZWvf77bDXgD9etlwAFD7xP1l9e6mBk+WI4jKJJfB2DVPyzdIc8wLtaCSfhXJS9YBQSRCKrQb556Oz9zsH6Jie/VyrecWDD2+PcBGYo0tbefV/bHT50L6lrawNLirNl8sa6Ng/I+6Sg2ocmeQFGHdSIMZcyScZmGx+4e18omi65kP5q5x/yWn+1FdKnJqgLTFuwaBPiKWxdCHvSR2UxhYQLvM/wIKcJ67I4X+V4vuhr59mL8XvVI80t/iG6Q4wCJ4FwJ8PHPgDBw7yeeDfy871pnbhoef370Gf3oQ0CVS03fm6Kb9QncsCFDAJx5CU33Gat/T+5R7qJs4Dfc9avunsI9cfmjpRS3kqQD3FbFuM+L3vANFHNDIw7v8I38LxTXDfRXs/HaN5hPijB0XOOk1hg3vlPiLDEXtzmdsKl77nfSsvsY+3b8VWqcreoLKE6kW8Ltahz8GlaBB7gGlntPS7M2xFm1sLUHOU/CsGgF9/ZKhY0Ow0gdxwoT42tWFr1A5az6pzQ43mhE2uRcoBN9s8se7vCZGRiRjApJVb8bpsyOCMhBHTRak3l5v7TKgec4cUSHsApx0Y4JxEP3XrLGizmqNvI6NHD7wlMkebfPU3wRr/NL66Cob7GuzgjC48sobPx+CkbDLXOvUQa4TcjVa1HKvNkFQnWR0hwGk2uSwOKZvPHWA9He9CM0vPVH5xs9PmvjkPYniBopCHMPvW9fvXY8i7+Yv/1T8VVzvtRtjfI9UEUSB6YHOGZ6Nhq3H+ZfMibzzI3x5O7VVbmuUrid/qQHajymLFQLpy7hSXcDUYK0sXv82TMlEjS9y97C64RHx/rAnpLC+wLNC7JoRAIIEnr+bmu2C00+1+ZtQHTF97nWFkhl/AytBWVepT0hY/9HuR/rAGjsYfbisQcSZKHnYoyR/r+wqX0bYjFO4Ys3fb6XZ9pGWLa5SoRaVudyTcIeYJ9ATWM6sIU8IsVWdRU8YPVhuR+ZHSbT0r4M4msPNVm22Fg/vvyTDv3Oy9TOUbnh12GNfzcIcBXNbDHh/vNe46immZKBkFz/eG7r8kR4etqKTeH5a3zIVilKE6EdtrbqUpe67CkadQ0N8eCEFzEY4YcDJe/IYfcvfhKopgGfktJpparreGpDFnlcsMYiLzpXv68/7hoYQvUB47N5Cbqo3aVYxEEeMpH3y/81vz43HzcP/T/uGpK1gRTb2UlY6I3DOH96Em1MIArfygrQ1Bb8BqHg7Ier//+fiseXz48d3Bh+Yp+8PT4WkpAuAMC6JW0x+N0CUAq3wQBWjFObxpgZ8IGz849u/RbkArlCud6VpTm31YCnRRujvxbYr4TiAfk0flxPx1bvDhr6h0NT7+dW30+ef6Cq8BTR6shs/+TQc4n/e3QBXhYB12vq7CBb/TrZ3w0uS1rZMF7sMpc0IrRg9NAlIFotBtVDoOUzvCr9v0J+phuG572JPptr2Fg2P9SZlkSoqiQvfC3meVG3BOgr8FLC7s5fyl/6c/AgV3HjAg86f9ziAY8mfWuAYOfVNYAWBQtbWOu9CBG234AJcXH8z+nTY9j4Ag4He2LlIoPjakGtvLGswm5E37slhyCg4giovUiqwOZIwQd5yghhwARSa/sfc07ISzCN6iRfoPFegqETdtMWFsQWlaOJiA2s3vQnf6wR1vkEKXlieF+WvB2jZ5EySNTeV8pfGoMwdaWd3JYmZH1tca32OwF8ljlW+k3Y8nh0dsN4N2AZULBc9zP/98AtD1gOL5AMICbdtHuWUR4WBJeWZ4370fUOvw02cPdA6X4Tc+6mS2ErdNooqR+qAGOz45+LRztg+LanfnPbh3HB8f7oPNdeHSZzS5LVevBDpmTy8LV2xv4UrkKmVfK4L8sO9V7XtN44JNkys8ThyfppBekPri8srKiqQulJK8iuhU6ATUGbEB9GzypAUT8mSf3GDYvm2+PTrc2z9JFpRnYoodm/djVcIVLqiX92lJOEQhCVFDy92g+VFKmkTBhjuHn3dO9mmgNIKFx7T6SebzB7EIMA5jmfuXp6LXpHkoxq4hNxRHzmMdHoW3KUu94MUCiuaQPzUGTIlE0dxKlTRk+koZA4BrVRvjPmO8pFUhxQZkGHyd9yHDDmTgR8Sf121DnI9KF+9SG5zYRIp4m3ChkmkIXbXqKZ19xfBYnemUH1Q+fa4Mq5XfP5Y6o9ovf+6s9N6fnh7u9u7vf//rt6Nf6n//uXRSH+53qzcrnc/Dbt3/fPXr7XL5996fb9+G33jrmHlqDTIIo1jwiJy2OLA2+GbJbUhjBbBMHcx88sBPqmJe2hNyXlF939BPMowzBfdmCrQ3QOZFxMfZ8Hf/nVcEBXreW5QXGOls+XtB73cY0tec6cXYUc0cfvBh72Tnl4Ozn4HgAqNZzCOcFflzNC+v+WNL/FDmj33FHMgYB7qI1B1PJknkEQDg1/By6C/uDsUZWVsW1meYZO43zGaE8gbehIxmFPkPtB+xHxRL1AQH5BLXWi367PDl3irjoY88KLkeysc+//x+99Qrjr6hCyxvfIWbkcCSrSdDbP7WcI+r3d3jv5c+/F799Nuve9+6l7eVy0+fVpfOzn45PvpYDn/5+2av9efO0n/vl3htyBet6oqXvIP+AOzLPgHqgiEt//5yGB7d8ofWxEFprtf4Cj149+m+1Vu7/632S7f1bu2+/a47/uP+mo8ihn9VV2rxaibxBTbQgyk8x1z1vBhmjA36Mhb0m6o2FuwNxr/VVywGQzYfeNiPwib3vGBM5W0/vOs3W72IPw372oBrkqPiQBOCaE0kMk7wy3309ROvkYxAAAppBZ3k1K6iGAUIYSuho2x20L/+ft25yulhjOyr7JyIdsMuybgMWaGeUCgnXDFYl+pCD64nVUB/DZFRQXqdk/VN0880eT69DjmAMNbCfIanq0ykQ/W1hK6CgTCZeVgA4Iz2uhQAR09dRYRe4Ku5qwsHcmftQAJ48F7vSzcY/giFMqzyoKxLHIFqbDQMJg0uFLXv50DdLuh1boJLdsq2nvawdSJme5q/C6Uxsvltm8f/LBasqU88zZ8RnuK9XRVRgjMpwzTFFwGQkxprGLT5SU984CxZDUwL1NMw/Ibtt7rRalqINnvdNe4sYqXjzi/v3lba726uWu/e/t2631k72D24//3sLT2LIWVwgliiuMEC3brxQS8UXZJHPH+IWB41vkK9xf5iFyDvfZabNHiuS3yVHl8BkNKz2Wk3Kw3pacsf5W9NFUSaWUTzbGAdQDG3hrDkI/86agjnigHbsO3OV/YZDfw+Gt2pAP3xzoXVnsyeWX45t1jxcqiV0EAL2c3LsH1fcP5ToWL/qYF0D9Y9dq0qr6leAYUFXayejZt9rCzDtwp87LKP6ip8W4EbO/BtDT64ygujyFaWASdOF17EtmXUQ7KrDkWSFaNxNAjgmJcBFxVIeqxcZkXvltSYJQz0u58+rXuRbuqRGVa/fnU1PAHP6zspRv7jgw/pdZQTlfBeLXMNibfAs/c1PGtIjMveZ71UwgAh0zVQ5ZnGGtD7ASqp49c28NplxYBhdBZoTcd9yE6XdXxKSId55LiXhjjqs65+043fxKMRw0Rk5SgBl+l1ug3lxa1UmxDq13V5Iu3WIK1MayDLtFPLtF2NRGOcFERkp2BKB8NhEx1YS5E/CLTdjJFMK7SZxaY9d3th29V0+r+Vf4OtSkk/U8qUqYw43SnkacnuQj0Pg9a6iVlCdTPj0a8xP03NWCcI5dOaHYWWZp8Sb8CHo8qDd0FlxXXOF48N0KY2x6OrVZQuQDfdQtLzoLb8o6FTxAikyjLj4za4NsYou/FIwkpGl/gA3zJCmY/meHTTiRY32wjpxYpA5q9GA3Dl19f39s+4Mujs9+P95v5vZ/sf9vb32KOcoaJirFIC9doTlWAbTOYI+uC7B0wYP554LFQNrF1mBBTMSBwvjevYO3BUgP2logATGQPk34p5XWjLCUCV9h7B2RHhCfsB4NvxnUEBDquIYaIlW/EIG64JrncBj212OFocpoJXSmn60gQEUZ2OAXMsHbvMmo1ks6qs9PbEpPWQZls9Fldvmbf4q1AqNeSYFSH4swmRn0F/TJ0DKvzh4+Gh6Nkvp+PL9+wu75rfBgYDvDmybBb3+6MhxtM2f9n/bX/Xy0GnuI+5TmU9M+Raq1MLAGAdJEbRAKN47aO1LOqCoQiVm3RcC7upVCp2oqZMDauKIOOvJVh2P58e6RUqS5R6Zp2mwNYo7ydKzuBNlwYtb9GlWdPRzMHuTXTtiG7CO3A8l4+a4X5gOZ25VhiOaeDfsIJtAZCRRRs20W6KHae45qSnBEaEwNbTlsOwB6SOcU9VzoBhRDJmHGZz1lD5r4ngDhlhkV60rvfDG1TN8MeoFR5AwlbddtK47PHoX5K5ewO5XP76xk90XcX+1zd+n3vr0Hj3uPbB4EJXKPveyrxulcpvi9JCOHuZ95l2IfN75nq9k/ElReFWRKGfTc2HS6Vtvs7QCfIhgUkT3SYbUcUiy03uzzzvOFYwhfEeSfwjlU9G2RLBgsy7WeOOd+0QbcucSmR1N+0R4wwuChqjyabJvEJP8ayzrFJ0XUFLyYAHikH3KJR8Z+9o76fmMV7XDaRYcnFzCCfbsAm/gAGM9DJ/8OoRtQGySf68v7O3+ebs4Oxwf/Ng76cDD+APUXu0yItiMI3y5oVgeHb3Y78DmYU7qPp/x6QVIP/gMDvsoY7RtFZhIA0QsQ1xpo96xOShiYWdgV8b0s7NxAw23VV+KlMcDBgD4hljWmMmnvdHzctueO3JKAwfY+NNr44JCPztAKLvfb7jab9BhUzqM5at6A0G+SMmlxbDw+cQYrO6PNbHM6A5LGU4+XIB8kCEHwtw/PsI3AV5LLuleqEOSgQTiQXX6o+6TSgvF9RqWTikSb83TgqNOC09Sp6Pr7jg/AjEpQH0/UfwutJKsp+yFLwL4UKIKqFTLl8IGC9SBUS9xrbNTLs9NyCm3bM5DZ7VOA+e8pAGTsR+tRinN1LoBPwdUSUKZAsWsneH7PP2lpFQU8+mub2V0P09kFsrqwuZaMiQg7A2cjyegWzDp4XAnMSbp0DbePJ8pHgW8GITMv4SyfgNY+C0IVrS9Whxd9c0NMJC/Hk58Nvm5WyiIF6RmIVG34mvNngo1ifNrqd46HQ+JR17JjXVRgIEW7DCNgxsGKlN+2LnEhVG41SrJt5rPFRA984tWtg33XtsOsLHTPVqpIsm9w3b05uu5TbwU6AFYtsAszanb3AxdRgbVEnR5040sSbf0FymT4xDmGR91aIOku4MSC9uZJscC9nOJqfEEnhfUt80XRWtj+YqV8Dys5xce/Ic6+fns/cQ3wumyvMvby7y5hGOoVPLq/JZ9Gt/fcijl0+D4dcObm8wbxrMQQhr9W03HHbavlklBlMBoRQpvmHzgNca0FKQjMZXXQ5DBShGYiCB4WSb1zsva1olDH+ixGfDlj9UQndvcRMUC36/DZeFCamjIvs67WiMIoGsSmA7YtCvFfVmPOye/vcQXjoYAh/GH0RiXV+O5e3Td851GF53A7l9XlmT14mo5ATEw4SaLLk5EqBVrIdIxZF78YjBfSgXKo97fwQV7o2GYSSQOAce06I+cnJA5doidxkvcVpO83ioeFk11mR7smVrnZgSdlYTTvKp5MbEUWPjUC2Xy49uanWTt9aazLyXUOQhUxbNwo5CjNz+CTskPrw9eCdQmmF0LZn/kq+KVEWc/ZwImY3r/UXTE4SXa07zsGI2Hh8fNQOwNqs5zbO14XIFlLvBtbFCB+VwHdTx0ckZ43zYCl8tO8azoIbXymN83s+smxBKUHTWTZWWA6HXp/uHb9ndjUcQAWarib8lJqtj6x3x63WsfPIEOfi7yyiPQsvHpyoYWQPb2PuxfxkN0j53UejJ77cRymxzkz9M2mTlMNJvh7+hr5tB/CoUIVKlWEcI4eh2m3x+03gm9ubCq/lRMUviYXBv5hdTmOhYM4aSoIKhImDgUEpwibbgYthwsxM1L8ORRJwylW4xNzBe1sos8Qbr3Nc4sZJ/ObrdH654WVxjEVtkd3d3rFX/fsDOuCITGUq8hiWx5+SOTXBcTJZr3QbtJqbC9iTfJVIRWLRj5PHVjMUbQkAD1xPYhQNg3cpGlRrGPO8vOfTUuf/jvRfTObhwUXodt75+TRQgI1dMyzHNK7mCURxVcGKyu3DejPxWi0kJx+AirmRXAWWGr68XMVw7PU0Mbd7x8JMJtaobexPtaPEKNoxnzzpSZaOyCSaf4e+PMX7sQOdWBQC8ZR/FBgausw/84S30vaLbcL2i325r6tivYCFgNUP5XZQX13m1a8IrhCMYTHLLs0Cm391o5nNgLfd2znb4SrLydeP+wG9ZHHsmBMjxEcDQDVwBqSdH7zYR8bs4DWfDvC9yC1tD2aTu3PA6dT8cWV8AoQB7BvrqJPhbk7+ASxIzhb8/akDX0F59jRGizehmPGqDK5OOyzbRYSr2ER9F0s2d+CMEHzAXwCKf1k5fM/1NjHGcoIF45O8EBwjgWiaDTooNXChZHDOyt205hfI3Ef6f8lUZqLkmjjdU4wbBjW4wipp/jnsDWYa3CZa/WB/Yhn2UFVE9dRMXYH1diwr5+jMiJuV3ubuSQOnmjy5tiOT195lGBjYlcP/sa6c/qlVpm+KVRXaz902QC8bZ62XgJxRoB10wwIvNgWS5ogL00Muq56OB0yn9fbPYKnUcMDdBCKKXazQomputd3vJyHutysozQVcV8KhG3v4K93MECNDFnWtG/9Yzp/vh3tHJ4i46cWZYnxhBO+q/v4dhWqRYLvGT14Iwp3XDgNHqBv6wKWgijAASWjzHFD2GulSh5Jmyd7T78f3+h7PmydHRGW9M8FXeAgUTNr8SjJmnhRo07/wuUKuSR37dlaoEz4gwzkTSEec/LfvGBnn3SYJyqkBgamkYu8C7VuHx4z3/utO6DMOecjFw7h3u4qCCBeAOfxLN5eydtoU3NXe9RoeP5jAcVWoJXyfQsbUD4XLE1yHGmVRZTd+2v/WGjNEB9WC4OAjDLgCTrK+WS+w6L4tpMusY3+ePmPyaH7WAHafCvU4/oCrCHj+sMF5kKcXLk528wGq1yNOICbdyMuBMCBF5mPPGVYGLnxK3k90CwR3paPFhZYXxqcWFXO6hVuBUi9IIgrx34aU7Fehkg6I1wA3aHwxQmEd7bta0+i78GYBhGe9zeNysipcwbu9R5DLe1/wl0OOK5he+8sbXpscpgZ63+LCEJNQm/crTiyhxTIMYi3QRC7edkvDReiZRX2vCRQ7C2ZsnY0AKRg3/4vDKI+xC3P+0/fmio6iAWllnwxuJ1cr5T+fvsiPsD9vSeWyC0L2hmdqoq8WHGo0T/ofH9AN4zcrQ1QpGClCHRLMDwHe7aDifya/iELRLvHCNH4INU72OwTrNFqjXEy8je5sr6D9whyvlvkRm4w3VuUO/zWtpYXjVL1h9wTpt5cBUoaAAfLNTvxtEVxCU0NwLottmxZNiXyeiqM8rxixEN0wIjCDMnipAJzQAFRC6y4UOf7AqlgUXvzzuXFY1/FbgBsi6ivgzrkUz34IsyjvMW6QAzRrHx+BK3pTFvaotbjSwdINAJX6dggoMxLJjA8WQ3ihS12TZLqbPu0V4djgzU1uVkW80UqRHa/Yb5Q3j9xueJlorob4SFo4aRZQ4UcHLiGcTuTxudOWtrvFoCto02sEw23EBXiFA6am2utBPsGO2CaGe2gyyVdNG66Guu6ejnD8MG34VZVBjhRknNwTXjIPEKjRSifAFaFmmdVJtgJ0igRGdxdzQOW5/M5ysOCrVtkhbmXUpQ1w3vHYLyk9Iuw92WiwTuQX+tIC+fL/LZoJ3pyamXAohiDAJL7C1aTkP1QI3qIWu/oLVdKVbXolT+FoRqqcKxQwAS+H98AoxES5JQSPEPp4kG4l9KI4hOs7OaSsyrq/TDq8y3Nkd+iBdfEY3aPsQW2wZtrkQehCb9Da6g+PsR1wTgv62Q0JRY91D3QnEzSec3WAkNQZOuXIWxEaHvjjJUkCtE2W0YWUHcC9g7IpguijHDup+h+N+kxVqjS+DEUIIDLpjwYvajKwVcvSvVycdzG/evNk/Ois+VPFoXobPR3YhRVGs3CNzbCZFgIFD6pZSqZjfWrA9aO/dKmcnL0ASajQ04sdp6LZ2WhG/w59cE9sTVAGTAwxmCzlQJJecPyroSo+Z0jh5YL0rKGwvJaA7B8frSOKUMABl2WOc+MFCjPEzNLg8SIa3V+H2FJ6miXx8jdSP2f0mYqviGcz4Tf5glTv8alPMHZ0FnAFan71iCc5ZcH2m5gOKKIsXcjk1plQtyzajYjzli/d9sjuA0oVwdAJx/iiPvmhCgJhFoLElRCvwftdN8514Zm8Ns7D+JFHw8HFT3Yxe9SsgsT022Jmf+RxcMlE7CrvByfEuGbKIpV4YDlqMvMKFRQ6MFNCdR5W0MfvK5NHROx5E2O3eLWRHyDo/3UPG19N7ASi43bpJuQFuKrwWlA1gvm+qm3vB16AbDlSerl/ve4d/9m/flNhNXh7PctAoxODJNCGP5BErtzEHApdl8nMP1QL8QtmG7RAK83LdgsO4Xt6/NR6LJRBGHA2GsJBx3rOTrH+d2QVwU04S0ccdfd5glDlgnVVb5G672BEdX04xJLHX3QXVwvr6u2D00z2ZbI2TbYrpbHHzbUCCmeBnlimwpo6adxE2o5suEVZIGAk0hZyAhXIv/XaGOzTrxWxF++EocxWO+23c3VzYQS91QNpQGWjX34WjkE0Bsj8Q67CJ396UfL5e0CMdeHiUPR2Jk50HLK1forB/MmjxrfDAk9/mj/1hFOwjzDLVgcc62Hfug9Ft51fG6w/Drj6chcTI4qLhID2ckL0IBFwFHcbB/sE3l3uJAHeM2XC1zcWuA1ua4Ra7dtcrtofhAHAmQEHAq1qeb++R/zQ5Zggfa0L8tZ+LuDVwVUmP7Bwx7pyDYtvHdj9Ru8FXL4tz1rDqMWGyP8ogXD5kRmo7m4ed0QiYrvznoMOfRMF+hfvad0MJWuL9II9+aj8OUp5pZCT7aOwZzd01xfdEKAmkhf5JAcT0AuRKXE3ENfPzBwIXsyRsC63E8K/LwfCvmxsmpDLW41JKZvd9CknwXHGlVhnB8awM011fd6mMMxTkX0x2LWDJlZKRxpSRnb2wdQLxp1lN6YFJt+UvDFJiTycx94wMalwjQO2inLEKstw0EmbfYxaWKiXxZooiJtUvbIIHQWL0UIXBKD6HmgBOutkdoIntG+vPIn5yTSGGlmxw5QnPeslKQwgED3spb5gGEHRi4S0h/7BiDawja6M9Lo4/vSTYxoXDTivoR3Gf6cjufo/rWHFRWJYx0zQ6qiZtcHh7y+J0h0NGONXag5u2k4yUrRsWdmvi+ohP7YVOe9CnGRA+vxgeYnoyOEbnFRBTSpoAA29KnKS8BYEmxck7GBWiEXwlUdeHjA6rAjqDP0MKy9VUuWgylUJkh0o4/nxd+bz36ffbVv/Db2cfP3U/fyx7+Y9/1zvvO0sf3ve7Y3Zt/Pnt7dLZ7sEKFDy8V9fxod9OupedOn/obH/1v59+Gn7c//bpv2dvf3r/lnP45JWMzt3TSCGXK4GcoTz3eHO5u/rXZe/boPVzt3f5+cMwOA2//vqu2/m9Ouq0er9Uf909+dv/7dN98O6X+99P765/+bl7++vp7cpuv9yICS28NwhUV58GOOEEd+Vf/c+/X/+6+/b2jyL0CcG1H/87WNtj/wj3kA58XnGVb3Fv4ahcPjoqe4wwe48bYgfDxfIRhEDvr96d/b1z936v3Pn09m2t9emX/569Oyn/cfvHfvDzpz+Cj59++XQ7+u2/1dH97+VBeNb94J+yV76scWKyKoIRAFXO2nnW8fDg8x+Vy96Hsv95bfxb9VPd/+1DuXV/3fn8uVu5vO1++nzWqv5++0vIleDo+1sjTw3W1yMYfvYOWfeX/bXj9/BvD7vMSwOdWF2znUtxtRYbH2MsP/8xuOx9uv11V8w1F9r5iIJdYWszt8XbWebMz4xYdaPPn7pfq5XfP1/1ln/y8v9de//7AdeJoZcpOqGRDjgv4IYx1ofjN1BeZ4iOI/Q0PLBsf3JSl5zXWOZVUjwKLOV8ruHqTKC7IS/b542rQqHq4ustWdopQcLpXClg3Ao41tUKXrXgenVXNUwUYU1r2KhbaznGs5Fvl8q+rOUqwUZFWhPxvGA7zKwmNQpZEIW8Kg0rdLZOI7XkqSjMCjqFrmnD5DCONhiO6P3O3e/OxQwTjuXYCfAdRs3lU4IXYWOAmxtvrYIiQVU1F7X8Pqe2KSZQeh9QwWfFQ+zQrb4RofoVeKcq6dkfuBjHlfoVduhUvYuCS9HY2tgZXiwTGi46GPPJK5IcweMjpVfJimi6rKTzuYJXY+X4fSNadPfk4PgMy/GIUSrK1pfoFqgK/ugMdnh4OZsndtOrQ9pKVLGchWJr4GNoxsmIpKGOJWuok+FJQx3IGupkKPqECWObb7r+ZdDl6T8zKJo1cLtlqDIYISdD6U7xcmnzTYk/czmEX/QklaYUo6K8+KXXytOkyqqgi+wPQCmwP2CP5KLOmojniBOVP3775f6y9stVq/fpjv1l5HQJBK9CvNzvtU/3l7wuSsu4OgnxgzM5lKPdZQyIAK2RXIuMTHstI9NM9jPJJKmM77w2O3eacCoyOqM97qUxWgXZP6170pvJdEl+/P8A")));
$gX_FlexDBShe = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$gXX_FlexDBShe = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_ExceptFlex = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_AdwareSig = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_PhishingSig = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_JSVirSig = unserialize(gzinflate(/*1519495862*/base64_decode("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")));
$gX_JSVirSig = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_SusDB = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_SusDBPrio = unserialize(gzinflate(/*1519495862*/base64_decode("S7QysKquBQA=")));
$g_DeMapper = unserialize(base64_decode("YTo1OntzOjEwOiJ3aXphcmQucGhwIjtzOjM3OiJjbGFzcyBXZWxjb21lU3RlcCBleHRlbmRzIENXaXphcmRTdGVwIjtzOjE3OiJ1cGRhdGVfY2xpZW50LnBocCI7czozNzoieyBDVXBkYXRlQ2xpZW50OjpBZGRNZXNzYWdlMkxvZygiZXhlYyI7czoxMToiaW5jbHVkZS5waHAiO3M6NDg6IkdMT0JBTFNbIlVTRVIiXS0+SXNBdXRob3JpemVkKCkgJiYgJGFyQXV0aFJlc3VsdCI7czo5OiJzdGFydC5waHAiO3M6NjA6IkJYX1JPT1QuJy9tb2R1bGVzL21haW4vY2xhc3Nlcy9nZW5lcmFsL3VwZGF0ZV9kYl91cGRhdGVyLnBocCI7czoxMDoiaGVscGVyLnBocCI7czo1ODoiSlBsdWdpbkhlbHBlcjo6Z2V0UGx1Z2luKCJzeXN0ZW0iLCJvbmVjbGlja2NoZWNrb3V0X3ZtMyIpOyI7fQ=="));

//END_SIG
////////////////////////////////////////////////////////////////////////////
if (!isCli() && !isset($_SERVER['HTTP_USER_AGENT'])) {
  echo "#####################################################\n";
  echo "# Error: cannot run on php-cgi. Requires php as cli #\n";
  echo "#                                                   #\n";
  echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
  echo "#####################################################\n";
  exit;
}


if (version_compare(phpversion(), '5.3.1', '<')) {
  echo "#####################################################\n";
  echo "# Warning: PHP Version < 5.3.1                      #\n";
  echo "# Some function might not work properly             #\n";
  echo "# See FAQ: http://revisium.com/ai/faq.php           #\n";
  echo "#####################################################\n";
  exit;
}

if (!(function_exists("file_put_contents") && is_callable("file_put_contents"))) {
    echo "#####################################################\n";
	echo "file_put_contents() is disabled. Cannot proceed.\n";
    echo "#####################################################\n";	
    exit;
}
                              
define('AI_VERSION', 'HOSTER-20180224');

////////////////////////////////////////////////////////////////////////////

$l_Res = '';

$g_Structure = array();
$g_Counter = 0;

$g_SpecificExt = false;

$g_UpdatedJsonLog = 0;
$g_NotRead = array();
$g_FileInfo = array();
$g_Iframer = array();
$g_PHPCodeInside = array();
$g_CriticalJS = array();
$g_Phishing = array();
$g_Base64 = array();
$g_HeuristicDetected = array();
$g_HeuristicType = array();
$g_UnixExec = array();
$g_SkippedFolders = array();
$g_UnsafeFilesFound = array();
$g_CMS = array();
$g_SymLinks = array();
$g_HiddenFiles = array();
$g_Vulnerable = array();

$g_RegExpStat = array();

$g_TotalFolder = 0;
$g_TotalFiles = 0;

$g_FoundTotalDirs = 0;
$g_FoundTotalFiles = 0;

if (!isCli()) {
   $defaults['site_url'] = 'http://' . $_SERVER['HTTP_HOST'] . '/'; 
}

define('CRC32_LIMIT', pow(2, 31) - 1);
define('CRC32_DIFF', CRC32_LIMIT * 2 -2);

error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);
srand(time());

set_time_limit(0);
ini_set('max_execution_time', '900000');
ini_set('realpath_cache_size','16M');
ini_set('realpath_cache_ttl','1200');
ini_set('pcre.backtrack_limit','1000000');
ini_set('pcre.recursion_limit','200000');
ini_set('pcre.jit','1');

if (!function_exists('stripos')) {
	function stripos($par_Str, $par_Entry, $Offset = 0) {
		return strpos(strtolower($par_Str), strtolower($par_Entry), $Offset);
	}
}

define('CMS_BITRIX', 'Bitrix');
define('CMS_WORDPRESS', 'Wordpress');
define('CMS_JOOMLA', 'Joomla');
define('CMS_DLE', 'Data Life Engine');
define('CMS_IPB', 'Invision Power Board');
define('CMS_WEBASYST', 'WebAsyst');
define('CMS_OSCOMMERCE', 'OsCommerce');
define('CMS_DRUPAL', 'Drupal');
define('CMS_MODX', 'MODX');
define('CMS_INSTANTCMS', 'Instant CMS');
define('CMS_PHPBB', 'PhpBB');
define('CMS_VBULLETIN', 'vBulletin');
define('CMS_SHOPSCRIPT', 'PHP ShopScript Premium');

define('CMS_VERSION_UNDEFINED', '0.0');

class CmsVersionDetector {
    private $root_path;
    private $versions;
    private $types;

    public function __construct($root_path = '.') {
        $this->root_path = $root_path;
        $this->versions = array();
        $this->types = array();

        $version = '';

        $dir_list = $this->getDirList($root_path);
        $dir_list[] = $root_path;

        foreach ($dir_list as $dir) {
            if ($this->checkBitrix($dir, $version)) {
               $this->addCms(CMS_BITRIX, $version);
            }

            if ($this->checkWordpress($dir, $version)) {
               $this->addCms(CMS_WORDPRESS, $version);
            }

            if ($this->checkJoomla($dir, $version)) {
               $this->addCms(CMS_JOOMLA, $version);
            }

            if ($this->checkDle($dir, $version)) {
               $this->addCms(CMS_DLE, $version);
            }

            if ($this->checkIpb($dir, $version)) {
               $this->addCms(CMS_IPB, $version);
            }

            if ($this->checkWebAsyst($dir, $version)) {
               $this->addCms(CMS_WEBASYST, $version);
            }

            if ($this->checkOsCommerce($dir, $version)) {
               $this->addCms(CMS_OSCOMMERCE, $version);
            }

            if ($this->checkDrupal($dir, $version)) {
               $this->addCms(CMS_DRUPAL, $version);
            }

            if ($this->checkMODX($dir, $version)) {
               $this->addCms(CMS_MODX, $version);
            }

            if ($this->checkInstantCms($dir, $version)) {
               $this->addCms(CMS_INSTANTCMS, $version);
            }

            if ($this->checkPhpBb($dir, $version)) {
               $this->addCms(CMS_PHPBB, $version);
            }

            if ($this->checkVBulletin($dir, $version)) {
               $this->addCms(CMS_VBULLETIN, $version);
            }

            if ($this->checkPhpShopScript($dir, $version)) {
               $this->addCms(CMS_SHOPSCRIPT, $version);
            }

        }
    }

    function getDirList($target) {
       $remove = array('.', '..'); 
       $directories = array_diff(scandir($target), $remove);

       $res = array();
           
       foreach($directories as $value) 
       { 
          if(is_dir($target . '/' . $value)) 
          {
             $res[] = $target . '/' . $value; 
          } 
       }

       return $res;
    }

    function isCms($name, $version) {
		for ($i = 0; $i < count($this->types); $i++) {
			if ((strpos($this->types[$i], $name) !== false) 
				&& 
			    (strpos($this->versions[$i], $version) !== false)) {
				return true;
			}
		}
    	
		return false;
    }

    function getCmsList() {
      return $this->types;
    }

    function getCmsVersions() {
      return $this->versions;
    }

    function getCmsNumber() {
      return count($this->types);
    }

    function getCmsName($index = 0) {
      return $this->types[$index];
    }

    function getCmsVersion($index = 0) {
      return $this->versions[$index];
    }

    private function addCms($type, $version) {
       $this->types[] = $type;
       $this->versions[] = $version;
    }

    private function checkBitrix($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/bitrix')) {
          $res = true;

          $tmp_content = @file_get_contents($this->root_path .'/bitrix/modules/main/classes/general/version.php');
          if (preg_match('|define\("SM_VERSION","(.+?)"\)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkWordpress($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/wp-admin')) {
          $res = true;

          $tmp_content = @file_get_contents($dir .'/wp-includes/version.php');
          if (preg_match('|\$wp_version\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }
       }

       return $res;
    }

    private function checkJoomla($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/libraries/joomla')) {
          $res = true;

          // for 1.5.x
          $tmp_content = @file_get_contents($dir .'/libraries/joomla/version.php');
          if (preg_match('|var\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];

             if (preg_match('|var\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version .= '.' . $tmp_ver[1];
             }
          }

          // for 1.7.x
          $tmp_content = @file_get_contents($dir .'/includes/version.php');
          if (preg_match('|public\s+\$RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];

             if (preg_match('|public\s+\$DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
                $version .= '.' . $tmp_ver[1];
             }
          }


	  // for 2.5.x and 3.x 
          $tmp_content = @file_get_contents($dir . '/libraries/cms/version/version.php');
   
          if (preg_match('|const\s+RELEASE\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
	      $version = $tmp_ver[1];
 
             if (preg_match('|const\s+DEV_LEVEL\s*=\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) { 
		$version .= '.' . $tmp_ver[1];
             }
          }

       }

       return $res;
    }

    private function checkDle($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir .'/engine/engine.php')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/engine/data/config.php');
          if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

          $tmp_content = @file_get_contents($dir . '/install.php');
          if (preg_match('|\'version_id\'\s*=>\s*"(.+?)"|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkIpb($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/ips_kernel')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/ips_kernel/class_xml.php');
          if (preg_match('|IP.Board\s+v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkWebAsyst($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/wbs/installer')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/license.txt');
          if (preg_match('|v([0-9\.]+)|si', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkOsCommerce($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/includes/version.php')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/includes/version.php');
          if (preg_match('|([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkDrupal($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/sites/all')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/CHANGELOG.txt');
          if (preg_match('|Drupal\s+([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkMODX($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/manager/assets')) {
          $res = true;

          // no way to pick up version
       }

       return $res;
    }

    private function checkInstantCms($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/plugins/p_usertab')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/index.php');
          if (preg_match('|InstantCMS\s+v([0-9\.]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkPhpBb($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/includes/acp')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/config.php');
          if (preg_match('|phpBB\s+([0-9\.x]+)|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }

    private function checkVBulletin($dir, &$version) {
          $version = CMS_VERSION_UNDEFINED;
          $res = false;
          if (file_exists($dir . '/core/includes/md5_sums_vbulletin.php'))
          {
                $res = true;
                require_once($dir . '/core/includes/md5_sums_vbulletin.php');
                $version = $md5_sum_versions['vb5_connect'];
          }
          else if(file_exists($dir . '/includes/md5_sums_vbulletin.php'))
          {
                $res = true;
                require_once($dir . '/includes/md5_sums_vbulletin.php');
                $version = $md5_sum_versions['vbulletin'];
          }
          return $res;
       }

    private function checkPhpShopScript($dir, &$version) {
       $version = CMS_VERSION_UNDEFINED;
       $res = false;

       if (file_exists($dir . '/install/consts.php')) {
          $res = true;

          $tmp_content = @file_get_contents($dir . '/install/consts.php');
          if (preg_match('|STRING_VERSION\',\s*\'(.+?)\'|smi', $tmp_content, $tmp_ver)) {
             $version = $tmp_ver[1];
          }

       }

       return $res;
    }
}

/**
 * Print file
*/
function printFile() {
	$l_FileName = $_GET['fn'];
	$l_CRC = isset($_GET['c']) ? (int)$_GET['c'] : 0;
	$l_Content = file_get_contents($l_FileName);
	$l_FileCRC = realCRC($l_Content);
	if ($l_FileCRC != $l_CRC) {
		echo 'Доступ запрещен.';
		exit;
	}
	
	echo '<pre>' . htmlspecialchars($l_Content) . '</pre>';
}

/**
 *
 */
function realCRC($str_in, $full = false)
{
        $in = crc32( $full ? normal($str_in) : $str_in );
        return ($in > CRC32_LIMIT) ? ($in - CRC32_DIFF) : $in;
}


/**
 * Determine php script is called from the command line interface
 * @return bool
 */
function isCli()
{
	return php_sapi_name() == 'cli';
}

function myCheckSum($str) {
   return hash('crc32b', $str);
}

 function generatePassword ($length = 9)
  {

    // start with a blank password
    $password = "";

    // define possible characters - any character in this string can be
    // picked for use in the password, so if you want to put vowels back in
    // or add special characters such as exclamation marks, this is where
    // you should do it
    $possible = "2346789bcdfghjkmnpqrtvwxyzBCDFGHJKLMNPQRTVWXYZ";

    // we refer to the length of $possible a few times, so let's grab it now
    $maxlength = strlen($possible);
  
    // check for length overflow and truncate if necessary
    if ($length > $maxlength) {
      $length = $maxlength;
    }
	
    // set up a counter for how many characters are in the password so far
    $i = 0; 
    
    // add random characters to $password until $length is reached
    while ($i < $length) { 

      // pick a random character from the possible ones
      $char = substr($possible, mt_rand(0, $maxlength-1), 1);
        
      // have we already used this character in $password?
      if (!strstr($password, $char)) { 
        // no, so it's OK to add it onto the end of whatever we've already got...
        $password .= $char;
        // ... and increase the counter by one
        $i++;
      }

    }

    // done!
    return $password;

  }

/**
 * Print to console
 * @param mixed $text
 * @param bool $add_lb Add line break
 * @return void
 */
function stdOut($text, $add_lb = true)
{
	if (!isCli())
		return;
		
	if (is_bool($text))
	{
		$text = $text ? 'true' : 'false';
	}
	else if (is_null($text))
	{
		$text = 'null';
	}
	if (!is_scalar($text))
	{
		$text = print_r($text, true);
	}

 	if (!BOOL_RESULT)
 	{
 		@fwrite(STDOUT, $text . ($add_lb ? "\n" : ''));
 	}
}

/**
 * Print progress
 * @param int $num Current file
 */
function printProgress($num, &$par_File)
{
	global $g_CriticalPHP, $g_Base64, $g_Phishing, $g_CriticalJS, $g_Iframer, $g_UpdatedJsonLog, 
               $g_AddPrefix, $g_NoPrefix;

	$total_files = $GLOBALS['g_FoundTotalFiles'];
	$elapsed_time = microtime(true) - START_TIME;
	$percent = number_format($total_files ? $num * 100 / $total_files : 0, 1);
	$stat = '';
	if ($elapsed_time >= 1)
	{
		$elapsed_seconds = round($elapsed_time, 0);
		$fs = floor($num / $elapsed_seconds);
		$left_files = $total_files - $num;
		if ($fs > 0) 
		{
		   $left_time = ($left_files / $fs); //ceil($left_files / $fs);
		   $stat = ' [Avg: ' . round($fs,2) . ' files/s' . ($left_time > 0  ? ' Left: ' . seconds2Human($left_time) : '') . '] [Mlw:' . (count($g_CriticalPHP) + count($g_Base64))  . '|' . (count($g_CriticalJS) + count($g_Iframer) + count($g_Phishing)) . ']';
        }
	}

        $l_FN = $g_AddPrefix . str_replace($g_NoPrefix, '', $par_File); 
	$l_FN = substr($par_File, -60);

	$text = "$percent% [$l_FN] $num of {$total_files}. " . $stat;
	$text = str_pad($text, 160, ' ', STR_PAD_RIGHT);
	stdOut(str_repeat(chr(8), 160) . $text, false);


      	$data = array('self' => __FILE__, 'started' => AIBOLIT_START_TIME, 'updated' => time(), 
                            'progress' => $percent, 'time_elapsed' => $elapsed_seconds, 
                            'time_left' => round($left_time), 'files_left' => $left_files, 
                            'files_total' => $total_files, 'current_file' => substr($g_AddPrefix . str_replace($g_NoPrefix, '', $par_File), -160));

        if (function_exists('aibolit_onProgressUpdate')) { aibolit_onProgressUpdate($data); }

	if (defined('PROGRESS_LOG_FILE') && 
           (time() - $g_UpdatedJsonLog > 1)) {
                if (function_exists('json_encode')) {
             	   file_put_contents(PROGRESS_LOG_FILE, json_encode($data));
                } else {
             	   file_put_contents(PROGRESS_LOG_FILE, serialize($data));
                }

		$g_UpdatedJsonLog = time();
        }
}

/**
 * Seconds to human readable
 * @param int $seconds
 * @return string
 */
function seconds2Human($seconds)
{
	$r = '';
	$_seconds = floor($seconds);
	$ms = $seconds - $_seconds;
	$seconds = $_seconds;
	if ($hours = floor($seconds / 3600))
	{
		$r .= $hours . (isCli() ? ' h ' : ' час ');
		$seconds = $seconds % 3600;
	}

	if ($minutes = floor($seconds / 60))
	{
		$r .= $minutes . (isCli() ? ' m ' : ' мин ');
		$seconds = $seconds % 60;
	}

	if ($minutes < 3) $r .= ' ' . $seconds + ($ms > 0 ? round($ms) : 0) . (isCli() ? ' s' : ' сек'); 

	return $r;
}

if (isCli())
{

	$cli_options = array(
                'c:' => 'avdb:',
		'm:' => 'memory:',
		's:' => 'size:',
		'a' => 'all',
		'd:' => 'delay:',
		'l:' => 'list:',
		'r:' => 'report:',
		'f' => 'fast',
		'j:' => 'file:',
		'p:' => 'path:',
		'q' => 'quite',
		'e:' => 'cms:',
		'x:' => 'mode:',
		'k:' => 'skip:',
		'i:' => 'idb:',
		'n' => 'sc',
		'o:' => 'json_report:',
		't:' => 'php_report:',
		'z:' => 'progress:',
		'g:' => 'handler:',
		'b' => 'smart',
		'h' => 'help',
	);

	$cli_longopts = array(
		'avdb:',
		'cmd:',
		'noprefix:',
		'addprefix:',
		'scan:',
		'one-pass',
		'smart',
		'quarantine',
		'with-2check',
		'skip-cache',
		'imake',
		'icheck'
	);
	
	$cli_longopts = array_merge($cli_longopts, array_values($cli_options));

	$options = getopt(implode('', array_keys($cli_options)), $cli_longopts);

	if (isset($options['h']) OR isset($options['help']))
	{
		$memory_limit = ini_get('memory_limit');
		echo <<<HELP
AI-Bolit - Professional Malware File Scanner.

Usage: php {$_SERVER['PHP_SELF']} [OPTIONS] [PATH]
Current default path is: {$defaults['path']}

  -j, --file=FILE      		Full path to single file to check
  -l, --list=FILE      		Full path to create plain text file with a list of found malware
  -o, --json_report=FILE	Full path to create json-file with a list of found malware
  -p, --path=PATH      		Directory path to scan, by default the file directory is used
                       		Current path: {$defaults['path']}
  -m, --memory=SIZE    		Maximum amount of memory a script may consume. Current value: $memory_limit
                       		Can take shorthand byte values (1M, 1G...)
  -s, --size=SIZE      		Scan files are smaller than SIZE. 0 - All files. Current value: {$defaults['max_size_to_scan']}
  -a, --all            		Scan all files (by default scan. js,. php,. html,. htaccess)
  -d, --delay=INT      		Delay in milliseconds when scanning files to reduce load on the file system (Default: 1)
  -x, --mode=INT       		Set scan mode. 0 - for basic, 1 - for expert and 2 for paranoic.
  -k, --skip=jpg,...   		Skip specific extensions. E.g. --skip=jpg,gif,png,xls,pdf
      --scan=php,...   		Scan only specific extensions. E.g. --scan=php,htaccess,js
  -r, --report=PATH/EMAILS
  -z, --progress=FILE  		Runtime progress of scanning, saved to the file, full path required. 
  -g, --hander=FILE    		External php handler for different events, full path to php file required.
      --cmd="command [args...]"
      --smart                   Enable smart mode (skip cache files and optimize scanning)
                       		Run command after scanning
      --one-pass       		Do not calculate remaining time
      --quarantine     		Archive all malware from report
      --with-2check    		Create or use AI-BOLIT-DOUBLECHECK.php file
      --imake
      --icheck
      --idb=file	   	Integrity Check database file

      --help           		Display this help and exit

* Mandatory arguments listed below are required for both full and short way of usage.

HELP;
		exit;
	}

	$l_FastCli = false;
	
	if (
		(isset($options['memory']) AND !empty($options['memory']) AND ($memory = $options['memory']))
		OR (isset($options['m']) AND !empty($options['m']) AND ($memory = $options['m']))
	)
	{
		$memory = getBytes($memory);
		if ($memory > 0)
		{
			$defaults['memory_limit'] = $memory;
			ini_set('memory_limit', $memory);
		}
	}


	$avdb = '';
	if (
		(isset($options['avdb']) AND !empty($options['avdb']) AND ($avdb = $options['avdb']))
		OR (isset($options['c']) AND !empty($options['c']) AND ($avdb = $options['c']))
	)
	{
		if (file_exists($avdb))
		{
			$defaults['avdb'] = $avdb;
		}
	}

	if (
		(isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false)
		OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)
	)
	{
		define('SCAN_FILE', $file);
	}


	if (
		(isset($options['list']) AND !empty($options['list']) AND ($file = $options['list']) !== false)
		OR (isset($options['l']) AND !empty($options['l']) AND ($file = $options['l']) !== false)
	)
	{

		define('PLAIN_FILE', $file);
	}

	if (
		(isset($options['json_report']) AND !empty($options['json_report']) AND ($file = $options['json_report']) !== false)
		OR (isset($options['o']) AND !empty($options['o']) AND ($file = $options['o']) !== false)
	)
	{
		define('JSON_FILE', $file);
	}

	if (
		(isset($options['php_report']) AND !empty($options['php_report']) AND ($file = $options['php_report']) !== false)
		OR (isset($options['t']) AND !empty($options['t']) AND ($file = $options['t']) !== false)
	)
	{
		define('PHP_FILE', $file);
	}

	if (isset($options['smart']) OR isset($options['b']))
	{
		define('SMART_SCAN', 1);
	}

	if (
		(isset($options['handler']) AND !empty($options['handler']) AND ($file = $options['handler']) !== false)
		OR (isset($options['g']) AND !empty($options['g']) AND ($file = $options['g']) !== false)
	)
	{
	        if (file_exists($file)) {
		   define('AIBOLIT_EXTERNAL_HANDLER', $file);
                }
	}

	if (
		(isset($options['progress']) AND !empty($options['progress']) AND ($file = $options['progress']) !== false)
		OR (isset($options['z']) AND !empty($options['z']) AND ($file = $options['z']) !== false)
	)
	{
		define('PROGRESS_LOG_FILE', $file);
	}
	if (
		(isset($options['size']) AND !empty($options['size']) AND ($size = $options['size']) !== false)
		OR (isset($options['s']) AND !empty($options['s']) AND ($size = $options['s']) !== false)
	)
	{
		$size = getBytes($size);
		$defaults['max_size_to_scan'] = $size > 0 ? $size : 0;
	}

 	if (
 		(isset($options['file']) AND !empty($options['file']) AND ($file = $options['file']) !== false)
 		OR (isset($options['j']) AND !empty($options['j']) AND ($file = $options['j']) !== false)
 		AND (isset($options['q'])) 
 	
 	)
 	{
 		$BOOL_RESULT = true;
 	}
 
	if (isset($options['f'])) 
	{
	   $l_FastCli = true;
	}
		
	if (isset($options['q']) || isset($options['quite'])) 
	{
 	    $BOOL_RESULT = true;
	}

        if (isset($options['x'])) {
            define('AI_EXPERT', $options['x']);
        } else if (isset($options['mode'])) {
            define('AI_EXPERT', $options['mode']);
        } else {
            define('AI_EXPERT', AI_EXPERT_MODE); 
        }

        if (AI_EXPERT < 2) {
           $g_SpecificExt = true;
           $defaults['scan_all_files'] = false;
        } else {
           $defaults['scan_all_files'] = true;
        }	

	define('BOOL_RESULT', $BOOL_RESULT);

	if (
		(isset($options['delay']) AND !empty($options['delay']) AND ($delay = $options['delay']) !== false)
		OR (isset($options['d']) AND !empty($options['d']) AND ($delay = $options['d']) !== false)
	)
	{
		$delay = (int) $delay;
		if (!($delay < 0))
		{
			$defaults['scan_delay'] = $delay;
		}
	}

	if (
		(isset($options['skip']) AND !empty($options['skip']) AND ($ext_list = $options['skip']) !== false)
		OR (isset($options['k']) AND !empty($options['k']) AND ($ext_list = $options['k']) !== false)
	)
	{
		$defaults['skip_ext'] = $ext_list;
	}

	if (isset($options['n']) OR isset($options['skip-cache']))
	{
		$defaults['skip_cache'] = true;
	}

	if (isset($options['scan']))
	{
		$ext_list = strtolower(trim($options['scan'], " ,\t\n\r\0\x0B"));
		if ($ext_list != '')
		{
			$l_FastCli = true;
			$g_SensitiveFiles = explode(",", $ext_list);
			for ($i = 0; $i < count($g_SensitiveFiles); $i++) {
			   if ($g_SensitiveFiles[$i] == '.') {
                              $g_SensitiveFiles[$i] = '';
                           }
                        }

			$g_SpecificExt = true;
		}
	}


    if (isset($options['all']) OR isset($options['a']))
    {
    	$defaults['scan_all_files'] = true;
        $g_SpecificExt = false;
    }

    if (isset($options['cms'])) {
        define('CMS', $options['cms']);
    } else if (isset($options['e'])) {
        define('CMS', $options['e']);
    }


    if (!defined('SMART_SCAN')) {
       define('SMART_SCAN', 1);
    }


	$l_SpecifiedPath = false;
	if (
		(isset($options['path']) AND !empty($options['path']) AND ($path = $options['path']) !== false)
		OR (isset($options['p']) AND !empty($options['p']) AND ($path = $options['p']) !== false)
	)
	{
		$defaults['path'] = $path;
		$l_SpecifiedPath = true;
	}

	if (
		isset($options['noprefix']) AND !empty($options['noprefix']) AND ($g_NoPrefix = $options['noprefix']) !== false)
		
	{
	} else {
		$g_NoPrefix = '';
	}

	if (
		isset($options['addprefix']) AND !empty($options['addprefix']) AND ($g_AddPrefix = $options['addprefix']) !== false)
		
	{
	} else {
		$g_AddPrefix = '';
	}



	$l_SuffixReport = str_replace('/var/www', '', $defaults['path']);
	$l_SuffixReport = str_replace('/home', '', $l_SuffixReport);
        $l_SuffixReport = preg_replace('#[/\\\.\s]#', '_', $l_SuffixReport);
	$l_SuffixReport .=  "-" . rand(1, 999999);
		
	if (
		(isset($options['report']) AND ($report = $options['report']) !== false)
		OR (isset($options['r']) AND ($report = $options['r']) !== false)
	)
	{
		$report = str_replace('@PATH@', $l_SuffixReport, $report);
		$report = str_replace('@RND@', rand(1, 999999), $report);
		$report = str_replace('@DATE@', date('d-m-Y-h-i'), $report);
		define('REPORT', $report);
		define('NEED_REPORT', true);
	}

	if (
		(isset($options['idb']) AND ($ireport = $options['idb']) !== false)
	)
	{
		$ireport = str_replace('@PATH@', $l_SuffixReport, $ireport);
		$ireport = str_replace('@RND@', rand(1, 999999), $ireport);
		$ireport = str_replace('@DATE@', date('d-m-Y-h-i'), $ireport);
		define('INTEGRITY_DB_FILE', $ireport);
	}

  
	defined('REPORT') OR define('REPORT', 'AI-BOLIT-REPORT-' . $l_SuffixReport . '-' . date('d-m-Y_H-i') . '.html');
	
	defined('INTEGRITY_DB_FILE') OR define('INTEGRITY_DB_FILE', 'AINTEGRITY-' . $l_SuffixReport . '-' . date('d-m-Y_H-i'));

	$last_arg = max(1, sizeof($_SERVER['argv']) - 1);
	if (isset($_SERVER['argv'][$last_arg]))
	{
		$path = $_SERVER['argv'][$last_arg];
		if (
			substr($path, 0, 1) != '-'
			AND (substr($_SERVER['argv'][$last_arg - 1], 0, 1) != '-' OR array_key_exists(substr($_SERVER['argv'][$last_arg - 1], -1), $cli_options)))
		{
			$defaults['path'] = $path;
		}
	}	
	
	
	define('ONE_PASS', isset($options['one-pass']));

	define('IMAKE', isset($options['imake']));
	define('ICHECK', isset($options['icheck']));

	if (IMAKE && ICHECK) die('One of the following options must be used --imake or --icheck.');

} else {
   define('AI_EXPERT', AI_EXPERT_MODE); 
   define('ONE_PASS', true);
}


if (isset($defaults['avdb']) && file_exists($defaults['avdb'])) {
   $avdb = explode("\n", gzinflate(base64_decode(str_rot13(strrev(trim(file_get_contents($defaults['avdb'])))))));

   $g_DBShe = explode("\n", base64_decode($avdb[0]));
   $gX_DBShe = explode("\n", base64_decode($avdb[1]));
   $g_FlexDBShe = explode("\n", base64_decode($avdb[2]));
   $gX_FlexDBShe = explode("\n", base64_decode($avdb[3]));
   $gXX_FlexDBShe = explode("\n", base64_decode($avdb[4]));
   $g_ExceptFlex = explode("\n", base64_decode($avdb[5]));
   $g_AdwareSig = explode("\n", base64_decode($avdb[6]));
   $g_PhishingSig = explode("\n", base64_decode($avdb[7]));
   $g_JSVirSig = explode("\n", base64_decode($avdb[8]));
   $gX_JSVirSig = explode("\n", base64_decode($avdb[9]));
   $g_SusDB = explode("\n", base64_decode($avdb[10]));
   $g_SusDBPrio = explode("\n", base64_decode($avdb[11]));
   $g_DeMapper = array_combine(explode("\n", base64_decode($avdb[12])), explode("\n", base64_decode($avdb[13])));

   if (count($g_DBShe) <= 1) {
      $g_DBShe = array();
   }

   if (count($gX_DBShe) <= 1) {
      $gX_DBShe = array();
   }

   if (count($g_FlexDBShe) <= 1) {
      $g_FlexDBShe = array();
   }

   if (count($gX_FlexDBShe) <= 1) {
      $gX_FlexDBShe = array();
   }

   if (count($gXX_FlexDBShe) <= 1) {
      $gXX_FlexDBShe = array();
   }

   if (count($g_ExceptFlex) <= 1) {
      $g_ExceptFlex = array();
   }

   if (count($g_AdwareSig) <= 1) {
      $g_AdwareSig = array();
   }

   if (count($g_PhishingSig) <= 1) {
      $g_PhishingSig = array();
   }

   if (count($gX_JSVirSig) <= 1) {
      $gX_JSVirSig = array();
   }

   if (count($g_JSVirSig) <= 1) {
      $g_JSVirSig = array();
   }

   if (count($g_SusDB) <= 1) {
      $g_SusDB = array();
   }

   if (count($g_SusDBPrio) <= 1) {
      $g_SusDBPrio = array();
   }

   stdOut('Loaded external signatures from ' . $defaults['avdb']);
}

// use only basic signature subset
if (AI_EXPERT < 2) {
   $gX_FlexDBShe = array();
   $gXX_FlexDBShe = array();
   $gX_JSVirSig = array();
}

stdOut('Malware signatures: ' . (count($g_JSVirSig) + count($gX_JSVirSig) + count($g_DBShe) + count($gX_DBShe) + count($gX_DBShe) + count($g_FlexDBShe) + count($gX_FlexDBShe) + count($gXX_FlexDBShe)));

if ($g_SpecificExt) {
  stdOut("Scan specific extensions: " . implode(',', $g_SensitiveFiles));
}

if (!DEBUG_PERFORMANCE) {
   OptimizeSignatures();
} else {
   stdOut("Debug Performance Scan");
}

$g_DBShe  = array_map('strtolower', $g_DBShe);
$gX_DBShe = array_map('strtolower', $gX_DBShe);

if (!defined('PLAIN_FILE')) { define('PLAIN_FILE', ''); }

// Init
define('MAX_ALLOWED_PHP_HTML_IN_DIR', 600);
define('BASE64_LENGTH', 69);
define('MAX_PREVIEW_LEN', 80);
define('MAX_EXT_LINKS', 1001);

if (defined('AIBOLIT_EXTERNAL_HANDLER')) {
   include_once(AIBOLIT_EXTERNAL_HANDLER);
   stdOut("\nLoaded external handler: " . AIBOLIT_EXTERNAL_HANDLER . "\n");
   if (function_exists("aibolit_onStart")) { aibolit_onStart(); }
}

// Perform full scan when running from command line
if (isset($_GET['full'])) {
  $defaults['scan_all_files'] = 1;
}

if ($l_FastCli) {
  $defaults['scan_all_files'] = 0; 
}

if (!isCli()) {
  	define('ICHECK', isset($_GET['icheck']));
  	define('IMAKE', isset($_GET['imake']));
	
	define('INTEGRITY_DB_FILE', 'ai-integrity-db');
}

define('SCAN_ALL_FILES', (bool) $defaults['scan_all_files']);
define('SCAN_DELAY', (int) $defaults['scan_delay']);
define('MAX_SIZE_TO_SCAN', getBytes($defaults['max_size_to_scan']));

if ($defaults['memory_limit'] AND ($defaults['memory_limit'] = getBytes($defaults['memory_limit'])) > 0) {
	ini_set('memory_limit', $defaults['memory_limit']);
    stdOut("Changed memory limit to " . $defaults['memory_limit']);
}

define('ROOT_PATH', realpath($defaults['path']));

if (!ROOT_PATH)
{
    if (isCli())  {
		die(stdOut("Directory '{$defaults['path']}' not found!"));
	}
}
elseif(!is_readable(ROOT_PATH))
{
        if (isCli())  {
		die2(stdOut("Cannot read directory '" . ROOT_PATH . "'!"));
	}
}

define('CURRENT_DIR', getcwd());
chdir(ROOT_PATH);

if (isCli() AND REPORT !== '' AND !getEmails(REPORT))
{
	$report = str_replace('\\', '/', REPORT);
	$abs = strpos($report, '/') === 0 ? DIR_SEPARATOR : '';
	$report = array_values(array_filter(explode('/', $report)));
	$report_file = array_pop($report);
	$report_path = realpath($abs . implode(DIR_SEPARATOR, $report));

	define('REPORT_FILE', $report_file);
	define('REPORT_PATH', $report_path);

	if (REPORT_FILE AND REPORT_PATH AND is_file(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE))
	{
		@unlink(REPORT_PATH . DIR_SEPARATOR . REPORT_FILE);
	}
}

if (defined('REPORT_PATH')) {
   $l_ReportDirName = REPORT_PATH;
}

define('QUEUE_FILENAME', ($l_ReportDirName != '' ? $l_ReportDirName . '/' : '') . 'AI-BOLIT-QUEUE-' . md5($defaults['path']) . '-' . rand(1000,9999) . '.txt');

if (function_exists('phpinfo')) {
   ob_start();
   phpinfo();
   $l_PhpInfo = ob_get_contents();
   ob_end_clean();

   $l_PhpInfo = str_replace('border: 1px', '', $l_PhpInfo);
   preg_match('|<body>(.*)</body>|smi', $l_PhpInfo, $l_PhpInfoBody);
}

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MODE@@", AI_EXPERT . '/' . SMART_SCAN, $l_Template);

if (AI_EXPERT == 0) {
   $l_Result .= '<div class="rep">' . AI_STR_057 . '</div>'; 
} else {
}

$l_Template = str_replace('@@HEAD_TITLE@@', AI_STR_051 . $g_AddPrefix . str_replace($g_NoPrefix, '', ROOT_PATH), $l_Template);

define('QCR_INDEX_FILENAME', 'fn');
define('QCR_INDEX_TYPE', 'type');
define('QCR_INDEX_WRITABLE', 'wr');
define('QCR_SVALUE_FILE', '1');
define('QCR_SVALUE_FOLDER', '0');

/**
 * Extract emails from the string
 * @param string $email
 * @return array of strings with emails or false on error
 */
function getEmails($email)
{
	$email = preg_split('#[,\s;]#', $email, -1, PREG_SPLIT_NO_EMPTY);
	$r = array();
	for ($i = 0, $size = sizeof($email); $i < $size; $i++)
	{
	        if (function_exists('filter_var')) {
   		   if (filter_var($email[$i], FILTER_VALIDATE_EMAIL))
   		   {
   		   	$r[] = $email[$i];
    		   }
                } else {
                   // for PHP4
                   if (strpos($email[$i], '@') !== false) {
   		   	$r[] = $email[$i];
                   }
                }
	}
	return empty($r) ? false : $r;
}

/**
 * Get bytes from shorthand byte values (1M, 1G...)
 * @param int|string $val
 * @return int
 */
function getBytes($val)
{
	$val = trim($val);
	$last = strtolower($val{strlen($val) - 1});
	switch($last) {
		case 't':
			$val *= 1024;
		case 'g':
			$val *= 1024;
		case 'm':
			$val *= 1024;
		case 'k':
			$val *= 1024;
	}
	return intval($val);
}

/**
 * Format bytes to human readable
 * @param int $bites
 * @return string
 */
function bytes2Human($bites)
{
	if ($bites < 1024)
	{
		return $bites . ' b';
	}
	elseif (($kb = $bites / 1024) < 1024)
	{
		return number_format($kb, 2) . ' Kb';
	}
	elseif (($mb = $kb / 1024) < 1024)
	{
		return number_format($mb, 2) . ' Mb';
	}
	elseif (($gb = $mb / 1024) < 1024)
	{
		return number_format($gb, 2) . ' Gb';
	}
	else
	{
		return number_format($gb / 1024, 2) . 'Tb';
	}
}

///////////////////////////////////////////////////////////////////////////
function needIgnore($par_FN, $par_CRC) {
  global $g_IgnoreList;
  
  for ($i = 0; $i < count($g_IgnoreList); $i++) {
     if (strpos($par_FN, $g_IgnoreList[$i][0]) !== false) {
		if ($par_CRC == $g_IgnoreList[$i][1]) {
			return true;
		}
	 }
  }
  
  return false;
}

///////////////////////////////////////////////////////////////////////////
function makeSafeFn($par_Str, $replace_path = false) {
  global $g_AddPrefix, $g_NoPrefix;
  if ($replace_path) {
     $lines = explode("\n", $par_Str);
     array_walk($lines, function(&$n) {
          global $g_AddPrefix, $g_NoPrefix;
          $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n); 
     }); 

     $par_Str = implode("\n", $lines);
  }
 
  return htmlspecialchars($par_Str, ENT_SUBSTITUTE | ENT_QUOTES);
}

function replacePathArray($par_Arr) {
  global $g_AddPrefix, $g_NoPrefix;
     array_walk($par_Arr, function(&$n) {
          global $g_AddPrefix, $g_NoPrefix;
          $n = $g_AddPrefix . str_replace($g_NoPrefix, '', $n); 
     }); 

  return $par_Arr;
}

///////////////////////////////////////////////////////////////////////////
function getRawJsonVuln($par_List) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
   $results = array();
   $l_Src = array('&quot;', '&lt;', '&gt;', '&amp;', '&#039;', '<' . '?php.');
   $l_Dst = array('"',      '<',    '>',    '&', '\'',         '<' . '?php ');

   for ($i = 0; $i < count($par_List); $i++) {
      $l_Pos = $par_List[$i]['ndx'];
      $res['fn'] = $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]);
      $res['sig'] = $par_List[$i]['id'];

      $res['ct'] = $g_Structure['c'][$l_Pos];
      $res['mt'] = $g_Structure['m'][$l_Pos];
      $res['sz'] = $g_Structure['s'][$l_Pos];
      $res['sigid'] = 'vuln_' . md5($g_Structure['n'][$l_Pos] . $par_List[$i]['id']);

      $results[] = $res; 
   }

   return $results;
}

///////////////////////////////////////////////////////////////////////////
function getRawJson($par_List, $par_Details = null, $par_SigId = null) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
   $results = array();
   $l_Src = array('&quot;', '&lt;', '&gt;', '&amp;', '&#039;', '<' . '?php.');
   $l_Dst = array('"',      '<',    '>',    '&', '\'',         '<' . '?php ');

   for ($i = 0; $i < count($par_List); $i++) {
       if ($par_SigId != null) {
          $l_SigId = 'id_' . $par_SigId[$i];
       } else {
          $l_SigId = 'id_n' . rand(1000000, 9000000);
       }
       


      $l_Pos = $par_List[$i];
      $res['fn'] = $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]);
      if ($par_Details != null) {
         $res['sig'] = preg_replace('|(L\d+).+__AI_MARKER__|smi', '[$1]: ...', $par_Details[$i]);
         $res['sig'] = preg_replace('/[^\x20-\x7F]/', '.', $res['sig']);
         $res['sig'] = preg_replace('/__AI_LINE1__(\d+)__AI_LINE2__/', '[$1] ', $res['sig']);
         $res['sig'] = preg_replace('/__AI_MARKER__/', ' @!!!>', $res['sig']);
         $res['sig'] = str_replace($l_Src, $l_Dst, $res['sig']);
      }

      $res['ct'] = $g_Structure['c'][$l_Pos];
      $res['mt'] = $g_Structure['m'][$l_Pos];
      $res['sz'] = $g_Structure['s'][$l_Pos];
      $res['sigid'] = $l_SigId;

      $results[] = $res; 
   }

   return $results;
}

///////////////////////////////////////////////////////////////////////////
function printList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
  
  $i = 0;

  if ($par_TableName == null) {
     $par_TableName = 'table_' . rand(1000000,9000000);
  }

  $l_Result = '';
  $l_Result .= "<div class=\"flist\"><table cellspacing=1 cellpadding=4 border=0 id=\"" . $par_TableName . "\">";

  $l_Result .= "<thead><tr class=\"tbgh" . ( $i % 2 ). "\">";
  $l_Result .= "<th width=70%>" . AI_STR_004 . "</th>";
  $l_Result .= "<th>" . AI_STR_005 . "</th>";
  $l_Result .= "<th>" . AI_STR_006 . "</th>";
  $l_Result .= "<th width=90>" . AI_STR_007 . "</th>";
  $l_Result .= "<th width=0 class=\"hidd\">CRC32</th>";
  $l_Result .= "<th width=0 class=\"hidd\"></th>";
  $l_Result .= "<th width=0 class=\"hidd\"></th>";
  $l_Result .= "<th width=0 class=\"hidd\"></th>";
  
  $l_Result .= "</tr></thead><tbody>";

  for ($i = 0; $i < count($par_List); $i++) {
    if ($par_SigId != null) {
       $l_SigId = 'id_' . $par_SigId[$i];
    } else {
       $l_SigId = 'id_z' . rand(1000000,9000000);
    }
    
    $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
         	if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
         		continue;
         	}
        }
  
     $l_Creat = $g_Structure['c'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['c'][$l_Pos]) : '-';
     $l_Modif = $g_Structure['m'][$l_Pos] > 0 ? date("d/m/Y H:i:s", $g_Structure['m'][$l_Pos]) : '-';
     $l_Size = $g_Structure['s'][$l_Pos] > 0 ? bytes2Human($g_Structure['s'][$l_Pos]) : '-';

     if ($par_Details != null) {
        $l_WithMarker = preg_replace('|__AI_MARKER__|smi', '<span class="marker">&nbsp;</span>', $par_Details[$i]);
        $l_WithMarker = preg_replace('|__AI_LINE1__|smi', '<span class="line_no">', $l_WithMarker);
        $l_WithMarker = preg_replace('|__AI_LINE2__|smi', '</span>', $l_WithMarker);
		
        $l_Body = '<div class="details">';

        if ($par_SigId != null) {
           $l_Body .= '<a href="#" onclick="return hsig(\'' . $l_SigId . '\')">[x]</a> ';
        }

        $l_Body .= $l_WithMarker . '</div>';
     } else {
        $l_Body = '';
     }

     $l_Result .= '<tr class="tbg' . ( $i % 2 ). '" o="' . $l_SigId .'">';
	 
	 if (is_file($g_Structure['n'][$l_Pos])) {
//		$l_Result .= '<td><div class="it"><a class="it" target="_blank" href="'. $defaults['site_url'] . 'ai-bolit.php?fn=' .
//	              $g_Structure['n'][$l_Pos] . '&ph=' . realCRC(PASS) . '&c=' . $g_Structure['crc'][$l_Pos] . '">' . $g_Structure['n'][$l_Pos] . '</a></div>' . $l_Body . '</td>';
		$l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos])) . '</a></div>' . $l_Body . '</td>';
	 } else {
		$l_Result .= '<td><div class="it"><a class="it">' . makeSafeFn($g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]])) . '</a></div></td>';
	 }
	 
     $l_Result .= '<td align=center><div class="ctd">' . $l_Creat . '</div></td>';
     $l_Result .= '<td align=center><div class="ctd">' . $l_Modif . '</div></td>';
     $l_Result .= '<td align=center><div class="ctd">' . $l_Size . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['crc'][$l_Pos] . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . 'x' . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . $g_Structure['m'][$l_Pos] . '</div></td>';
     $l_Result .= '<td class="hidd"><div class="hidd">' . $l_SigId . '</div></td>';
     $l_Result .= '</tr>';

  }

  $l_Result .= "</tbody></table></div><div class=clear style=\"margin: 20px 0 0 0\"></div>";

  return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function printPlainList($par_List, $par_Details = null, $par_NeedIgnore = false, $par_SigId = null, $par_TableName = null) {
  global $g_Structure, $g_NoPrefix, $g_AddPrefix;
  
  $l_Result = "";

  $l_Src = array('&quot;', '&lt;', '&gt;', '&amp;', '&#039;');
  $l_Dst = array('"',      '<',    '>',    '&', '\'');

  for ($i = 0; $i < count($par_List); $i++) {
    $l_Pos = $par_List[$i];
        if ($par_NeedIgnore) {
         	if (needIgnore($g_Structure['n'][$par_List[$i]], $g_Structure['crc'][$l_Pos])) {
         		continue;
         	}                      
        }
  

     if ($par_Details != null) {

        $l_Body = preg_replace('|(L\d+).+__AI_MARKER__|smi', '$1: ...', $par_Details[$i]);
        $l_Body = preg_replace('/[^\x20-\x7F]/', '.', $l_Body);
        $l_Body = str_replace($l_Src, $l_Dst, $l_Body);

     } else {
        $l_Body = '';
     }

	 if (is_file($g_Structure['n'][$l_Pos])) {		 
		$l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$l_Pos]) . "\t\t\t" . $l_Body . "\n";
	 } else {
		$l_Result .= $g_AddPrefix . str_replace($g_NoPrefix, '', $g_Structure['n'][$par_List[$i]]) . "\n";
	 }
	 
  }

  return $l_Result;
}

///////////////////////////////////////////////////////////////////////////
function extractValue(&$par_Str, $par_Name) {
  if (preg_match('|<tr><td class="e">\s*'.$par_Name.'\s*</td><td class="v">(.+?)</td>|sm', $par_Str, $l_Result)) {
     return str_replace('no value', '', strip_tags($l_Result[1]));
  }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ExtractInfo($par_Str) {
   $l_PhpInfoSystem = extractValue($par_Str, 'System');
   $l_PhpPHPAPI = extractValue($par_Str, 'Server API');
   $l_AllowUrlFOpen = extractValue($par_Str, 'allow_url_fopen');
   $l_AllowUrlInclude = extractValue($par_Str, 'allow_url_include');
   $l_DisabledFunction = extractValue($par_Str, 'disable_functions');
   $l_DisplayErrors = extractValue($par_Str, 'display_errors');
   $l_ErrorReporting = extractValue($par_Str, 'error_reporting');
   $l_ExposePHP = extractValue($par_Str, 'expose_php');
   $l_LogErrors = extractValue($par_Str, 'log_errors');
   $l_MQGPC = extractValue($par_Str, 'magic_quotes_gpc');
   $l_MQRT = extractValue($par_Str, 'magic_quotes_runtime');
   $l_OpenBaseDir = extractValue($par_Str, 'open_basedir');
   $l_RegisterGlobals = extractValue($par_Str, 'register_globals');
   $l_SafeMode = extractValue($par_Str, 'safe_mode');


   $l_DisabledFunction = ($l_DisabledFunction == '' ? '-?-' : $l_DisabledFunction);
   $l_OpenBaseDir = ($l_OpenBaseDir == '' ? '-?-' : $l_OpenBaseDir);

   $l_Result = '<div class="title">' . AI_STR_008 . ': ' . phpversion() . '</div>';
   $l_Result .= 'System Version: <span class="php_ok">' . $l_PhpInfoSystem . '</span><br/>';
   $l_Result .= 'PHP API: <span class="php_ok">' . $l_PhpPHPAPI. '</span><br/>';
   $l_Result .= 'allow_url_fopen: <span class="php_' . ($l_AllowUrlFOpen == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlFOpen. '</span><br/>';
   $l_Result .= 'allow_url_include: <span class="php_' . ($l_AllowUrlInclude == 'On' ? 'bad' : 'ok') . '">' . $l_AllowUrlInclude. '</span><br/>';
   $l_Result .= 'disable_functions: <span class="php_' . ($l_DisabledFunction == '-?-' ? 'bad' : 'ok') . '">' . $l_DisabledFunction. '</span><br/>';
   $l_Result .= 'display_errors: <span class="php_' . ($l_DisplayErrors == 'On' ? 'ok' : 'bad') . '">' . $l_DisplayErrors. '</span><br/>';
   $l_Result .= 'error_reporting: <span class="php_ok">' . $l_ErrorReporting. '</span><br/>';
   $l_Result .= 'expose_php: <span class="php_' . ($l_ExposePHP == 'On' ? 'bad' : 'ok') . '">' . $l_ExposePHP. '</span><br/>';
   $l_Result .= 'log_errors: <span class="php_' . ($l_LogErrors == 'On' ? 'ok' : 'bad') . '">' . $l_LogErrors . '</span><br/>';
   $l_Result .= 'magic_quotes_gpc: <span class="php_' . ($l_MQGPC == 'On' ? 'ok' : 'bad') . '">' . $l_MQGPC. '</span><br/>';
   $l_Result .= 'magic_quotes_runtime: <span class="php_' . ($l_MQRT == 'On' ? 'bad' : 'ok') . '">' . $l_MQRT. '</span><br/>';
   $l_Result .= 'register_globals: <span class="php_' . ($l_RegisterGlobals == 'On' ? 'bad' : 'ok') . '">' . $l_RegisterGlobals . '</span><br/>';
   $l_Result .= 'open_basedir: <span class="php_' . ($l_OpenBaseDir == '-?-' ? 'bad' : 'ok') . '">' . $l_OpenBaseDir . '</span><br/>';
   
   if (phpversion() < '5.3.0') {
      $l_Result .= 'safe_mode (PHP < 5.3.0): <span class="php_' . ($l_SafeMode == 'On' ? 'ok' : 'bad') . '">' . $l_SafeMode. '</span><br/>';
   }

   return $l_Result . '<p>';
}

///////////////////////////////////////////////////////////////////////////
   function addSlash($dir) {
      return rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
   }

///////////////////////////////////////////////////////////////////////////
function QCR_Debug($par_Str = "") {
  if (!DEBUG_MODE) {
     return;
  }

  $l_MemInfo = ' ';  
  if (function_exists('memory_get_usage')) {
     $l_MemInfo .= ' curmem=' .  bytes2Human(memory_get_usage());
  }

  if (function_exists('memory_get_peak_usage')) {
     $l_MemInfo .= ' maxmem=' .  bytes2Human(memory_get_peak_usage());
  }

  stdOut("\n" . date('H:i:s') . ': ' . $par_Str . $l_MemInfo . "\n");
}


///////////////////////////////////////////////////////////////////////////
function QCR_ScanDirectories($l_RootDir)
{
	global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, 
			$defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, 
                        $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SensitiveFiles, 
						$g_SuspiciousFiles, $g_ShortListExt, $l_SkipSample;

	static $l_Buffer = '';

	$l_DirCounter = 0;
	$l_DoorwayFilesCounter = 0;
	$l_SourceDirIndex = $g_Counter - 1;

        $l_SkipSample = array();

	QCR_Debug('Scan ' . $l_RootDir);

        $l_QuotedSeparator = quotemeta(DIR_SEPARATOR); 
 	if ($l_DIRH = @opendir($l_RootDir))
	{
		while (($l_FileName = readdir($l_DIRH)) !== false)
		{
			if ($l_FileName == '.' || $l_FileName == '..') continue;

			$l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;

			$l_Type = filetype($l_FileName);
            if ($l_Type == "link") 
            {
                $g_SymLinks[] = $l_FileName;
                continue;
            } else			
			if ($l_Type != "file" && $l_Type != "dir" ) {
			        if (!in_array($l_FileName, $g_UnixExec)) {
				   $g_UnixExec[] = $l_FileName;
				}

				continue;
			}	
						
			$l_Ext = strtolower(pathinfo($l_FileName, PATHINFO_EXTENSION));
			$l_IsDir = is_dir($l_FileName);

			if (in_array($l_Ext, $g_SuspiciousFiles)) 
			{
			        if (!in_array($l_FileName, $g_UnixExec)) {
                		   $g_UnixExec[] = $l_FileName;
                                } 
            		}

			// which files should be scanned
			$l_NeedToScan = SCAN_ALL_FILES || (in_array($l_Ext, $g_SensitiveFiles));

			if (in_array(strtolower($l_Ext), $g_IgnoredExt)) {    
		           $l_NeedToScan = false;
                        }

      			// if folder in ignore list
      			$l_Skip = false;
      			for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
      				if (($g_DirIgnoreList[$dr] != '') &&
      				   preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
      				   if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                                      $l_SkipSample[] = $g_DirIgnoreList[$dr];
                                   } else {
        		             $l_Skip = true;
                                     $l_NeedToScan = false;
                                   }
      				}
      			}


			if ($l_IsDir)
			{
				// skip on ignore
				if ($l_Skip) {
				   $g_SkippedFolders[] = $l_FileName;
				   continue;
				}
				
				$l_BaseName = basename($l_FileName);

				if ((strpos($l_BaseName, '.') === 0) && ($l_BaseName != '.htaccess')) {
	               $g_HiddenFiles[] = $l_FileName;
	            }

//				$g_Structure['d'][$g_Counter] = $l_IsDir;
//				$g_Structure['n'][$g_Counter] = $l_FileName;
				if (ONE_PASS) {
					$g_Structure['n'][$g_Counter] = $l_FileName . DIR_SEPARATOR;
				} else {
					$l_Buffer .= $l_FileName . DIR_SEPARATOR . "\n";
				}

				$l_DirCounter++;

				if ($l_DirCounter > MAX_ALLOWED_PHP_HTML_IN_DIR)
				{
					$g_Doorway[] = $l_SourceDirIndex;
					$l_DirCounter = -655360;
				}

				$g_Counter++;
				$g_FoundTotalDirs++;

				QCR_ScanDirectories($l_FileName);
			} else
			{
				if ($l_NeedToScan)
				{
					$g_FoundTotalFiles++;
					if (in_array($l_Ext, $g_ShortListExt)) 
					{
						$l_DoorwayFilesCounter++;
						
						if ($l_DoorwayFilesCounter > MAX_ALLOWED_PHP_HTML_IN_DIR)
						{
							$g_Doorway[] = $l_SourceDirIndex;
							$l_DoorwayFilesCounter = -655360;
						}
					}

					if (ONE_PASS) {
						QCR_ScanFile($l_FileName, $g_Counter++);
					} else {
						$l_Buffer .= $l_FileName."\n";
					}

					$g_Counter++;
				}
			}

			if (strlen($l_Buffer) > 32000)
			{ 
				file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file ".QUEUE_FILENAME);
				$l_Buffer = '';
			}

		}

		closedir($l_DIRH);
	}
	
	if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
		file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
		$l_Buffer = '';                                                                            
	}

}


///////////////////////////////////////////////////////////////////////////
function getFragment($par_Content, $par_Pos) {
  $l_MaxChars = MAX_PREVIEW_LEN;
  $l_MaxLen = strlen($par_Content);
  $l_RightPos = min($par_Pos + $l_MaxChars, $l_MaxLen); 
  $l_MinPos = max(0, $par_Pos - $l_MaxChars);

  $l_FoundStart = substr($par_Content, 0, $par_Pos);
  $l_FoundStart = str_replace("\r", '', $l_FoundStart);
  $l_LineNo = strlen($l_FoundStart) - strlen(str_replace("\n", '', $l_FoundStart)) + 1;

  $par_Content = preg_replace('/[\x00-\x1F\x80-\xFF]/', '~', $par_Content);

  $l_Res = '__AI_LINE1__' . $l_LineNo . "__AI_LINE2__  " . ($l_MinPos > 0 ? '…' : '') . substr($par_Content, $l_MinPos, $par_Pos - $l_MinPos) . 
           '__AI_MARKER__' . substr($par_Content, $par_Pos, $l_RightPos - $par_Pos - 1);

  $l_Res = makeSafeFn(UnwrapObfu($l_Res));
  $l_Res = str_replace('~', '·', $l_Res);
  $l_Res = preg_replace('/\s+/smi', ' ', $l_Res);
  $l_Res = str_replace('' . '?php', '' . '?php ', $l_Res);

  return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function escapedHexToHex($escaped)
{ $GLOBALS['g_EncObfu']++; return chr(hexdec($escaped[1])); }
function escapedOctDec($escaped)
{ $GLOBALS['g_EncObfu']++; return chr(octdec($escaped[1])); }
function escapedDec($escaped)
{ $GLOBALS['g_EncObfu']++; return chr($escaped[1]); }

///////////////////////////////////////////////////////////////////////////
if (!defined('T_ML_COMMENT')) {
   define('T_ML_COMMENT', T_COMMENT);
} else {
   define('T_DOC_COMMENT', T_ML_COMMENT);
}
          	
function UnwrapObfu($par_Content) {
  $GLOBALS['g_EncObfu'] = 0;
  
  $search  = array( ' ;', ' =', ' ,', ' .', ' (', ' )', ' {', ' }', '; ', '= ', ', ', '. ', '( ', '( ', '{ ', '} ', ' !', ' >', ' <', ' _', '_ ', '< ',  '> ', ' $', ' %',   '% ', '# ', ' #', '^ ', ' ^', ' &', '& ', ' ?', '? ');
  $replace = array(  ';',  '=',  ',',  '.',  '(',  ')',  '{',  '}', ';',  '=',  ',',  '.',  '(',   ')', '{',  '}',   '!',  '>',  '<',  '_', '_',  '<',   '>',   '$',  '%',   '%',  '#',   '#', '^',   '^',  '&', '&',   '?', '?');
  $par_Content = str_replace('@', '', $par_Content);
  $par_Content = preg_replace('~\s+~smi', ' ', $par_Content);
  $par_Content = str_replace($search, $replace, $par_Content);
  $par_Content = preg_replace_callback('~\bchr\(\s*([0-9a-fA-FxX]+)\s*\)~', function ($m) { return "'".chr(intval($m[1], 0))."'"; }, $par_Content );

  $par_Content = preg_replace_callback('/\\\\x([a-fA-F0-9]{1,2})/i','escapedHexToHex', $par_Content);
  $par_Content = preg_replace_callback('/\\\\([0-9]{1,3})/i','escapedOctDec', $par_Content);

  $par_Content = preg_replace('/[\'"]\s*?\.+\s*?[\'"]/smi', '', $par_Content);
  $par_Content = preg_replace('/[\'"]\s*?\++\s*?[\'"]/smi', '', $par_Content);

  $content = str_replace('<?$', '<?php$', $content);
  $content = str_replace('<?php', '<?php ', $content);

  return $par_Content;
}

///////////////////////////////////////////////////////////////////////////
// Unicode BOM is U+FEFF, but after encoded, it will look like this.
define ('UTF32_BIG_ENDIAN_BOM'   , chr(0x00) . chr(0x00) . chr(0xFE) . chr(0xFF));
define ('UTF32_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE) . chr(0x00) . chr(0x00));
define ('UTF16_BIG_ENDIAN_BOM'   , chr(0xFE) . chr(0xFF));
define ('UTF16_LITTLE_ENDIAN_BOM', chr(0xFF) . chr(0xFE));
define ('UTF8_BOM'               , chr(0xEF) . chr(0xBB) . chr(0xBF));

function detect_utf_encoding($text) {
    $first2 = substr($text, 0, 2);
    $first3 = substr($text, 0, 3);
    $first4 = substr($text, 0, 3);
    
    if ($first3 == UTF8_BOM) return 'UTF-8';
    elseif ($first4 == UTF32_BIG_ENDIAN_BOM) return 'UTF-32BE';
    elseif ($first4 == UTF32_LITTLE_ENDIAN_BOM) return 'UTF-32LE';
    elseif ($first2 == UTF16_BIG_ENDIAN_BOM) return 'UTF-16BE';
    elseif ($first2 == UTF16_LITTLE_ENDIAN_BOM) return 'UTF-16LE';

    return false;
}

///////////////////////////////////////////////////////////////////////////
function QCR_SearchPHP($src)
{
  if (preg_match("/(<\?php[\w\s]{5,})/smi", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
	  return $l_Found[0][1];
  }

  if (preg_match("/(<script[^>]*language\s*=\s*)('|\"|)php('|\"|)([^>]*>)/i", $src, $l_Found, PREG_OFFSET_CAPTURE)) {
    return $l_Found[0][1];
  }

  return false;
}


///////////////////////////////////////////////////////////////////////////
function knowUrl($par_URL) {
  global $g_UrlIgnoreList;

  for ($jk = 0; $jk < count($g_UrlIgnoreList); $jk++) {
     if  (stripos($par_URL, $g_UrlIgnoreList[$jk]) !== false) {
     	return true;
     }
  }

  return false;
}

///////////////////////////////////////////////////////////////////////////

function makeSummary($par_Str, $par_Number, $par_Style) {
   return '<tr><td class="' . $par_Style . '" width=400>' . $par_Str . '</td><td class="' . $par_Style . '">' . $par_Number . '</td></tr>';
}

///////////////////////////////////////////////////////////////////////////

function CheckVulnerability($par_Filename, $par_Index, $par_Content) {
    global $g_Vulnerable, $g_CmsListDetector;
	
	$l_Vuln = array();

        $par_Filename = strtolower($par_Filename);


	if (
	    (strpos($par_Filename, 'libraries/joomla/session/session.php') !== false) &&
		(strpos($par_Content, '&& filter_var($_SERVER[\'HTTP_X_FORWARDED_FOR') === false)
		) 
	{		
			$l_Vuln['id'] = 'RCE : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
	}

	if (
	    (strpos($par_Filename, 'administrator/components/com_media/helpers/media.php') !== false) &&
		(strpos($par_Content, '$format == \'\' || $format == false ||') === false)
		) 
	{		
		if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
			$l_Vuln['id'] = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (
	    (strpos($par_Filename, 'joomla/filesystem/file.php') !== false) &&
		(strpos($par_Content, '$file = rtrim($file, \'.\');') === false)
		) 
	{		
		if ($g_CmsListDetector->isCms(CMS_JOOMLA, '1.5')) {
			$l_Vuln['id'] = 'AFU : https://docs.joomla.org/Security_hotfixes_for_Joomla_EOL_versions';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if ((strpos($par_Filename, 'editor/filemanager/upload/test.html') !== false) ||
		(stripos($par_Filename, 'editor/filemanager/browser/default/connectors/php/') !== false) ||
		(stripos($par_Filename, 'editor/filemanager/connectors/uploadtest.html') !== false) ||
	   (strpos($par_Filename, 'editor/filemanager/browser/default/connectors/test.html') !== false)) {
		$l_Vuln['id'] = 'AFU : FCKEDITOR : http://www.exploit-db.com/exploits/17644/ & /exploit/249';
		$l_Vuln['ndx'] = $par_Index;
		$g_Vulnerable[] = $l_Vuln;
		return true;
	}

	if ((strpos($par_Filename, 'inc_php/image_view.class.php') !== false) ||
	    (strpos($par_Filename, '/inc_php/framework/image_view.class.php') !== false)) {
		if (strpos($par_Content, 'showImageByID') === false) {
			$l_Vuln['id'] = 'AFU : REVSLIDER : http://www.exploit-db.com/exploits/35385/';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if ((strpos($par_Filename, 'elfinder/php/connector.php') !== false) ||
	    (strpos($par_Filename, 'elfinder/elfinder.') !== false)) {
			$l_Vuln['id'] = 'AFU : elFinder';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
	}

	if (strpos($par_Filename, 'includes/database/database.inc') !== false) {
		if (strpos($par_Content, 'foreach ($data as $i => $value)') !== false) {
			$l_Vuln['id'] = 'SQLI : DRUPAL : CVE-2014-3704';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'engine/classes/min/index.php') !== false) {
		if (strpos($par_Content, 'tr_replace(chr(0)') === false) {
			$l_Vuln['id'] = 'AFD : MINIFY : CVE-2013-6619';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (( strpos($par_Filename, 'timthumb.php') !== false ) || 
	    ( strpos($par_Filename, 'thumb.php') !== false ) || 
	    ( strpos($par_Filename, 'cache.php') !== false ) || 
	    ( strpos($par_Filename, '_img.php') !== false )) {
		if (strpos($par_Content, 'code.google.com/p/timthumb') !== false && strpos($par_Content, '2.8.14') === false ) {
			$l_Vuln['id'] = 'RCE : TIMTHUMB : CVE-2011-4106,CVE-2014-4663';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'components/com_rsform/helpers/rsform.php') !== false) {
		if (strpos($par_Content, 'eval($form->ScriptDisplay);') !== false) {
			$l_Vuln['id'] = 'RCE : RSFORM : rsform.php, LINE 1605';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'fancybox-for-wordpress/fancybox.php') !== false) {
		if (strpos($par_Content, '\'reset\' == $_REQUEST[\'action\']') !== false) {
			$l_Vuln['id'] = 'CODE INJECTION : FANCYBOX';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}


	if (strpos($par_Filename, 'cherry-plugin/admin/import-export/upload.php') !== false) {
		if (strpos($par_Content, 'verify nonce') === false) {
			$l_Vuln['id'] = 'AFU : Cherry Plugin';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}
	
	
	if (strpos($par_Filename, 'tiny_mce/plugins/tinybrowser/tinybrowser.php') !== false) {	
		$l_Vuln['id'] = 'AFU : TINYMCE : http://www.exploit-db.com/exploits/9296/';
		$l_Vuln['ndx'] = $par_Index;
		$g_Vulnerable[] = $l_Vuln;
		
		return true;
	}

	if (strpos($par_Filename, '/bx_1c_import.php') !== false) {	
		if (strpos($par_Content, '$_GET[\'action\']=="getfiles"') !== false) {
   		   $l_Vuln['id'] = 'AFD : https://habrahabr.ru/company/dsec/blog/326166/';
   		   $l_Vuln['ndx'] = $par_Index;
   		   $g_Vulnerable[] = $l_Vuln;
   		
   		   return true;
                }
	}

	if (strpos($par_Filename, 'scripts/setup.php') !== false) {		
		if (strpos($par_Content, 'PMA_Config') !== false) {
			$l_Vuln['id'] = 'CODE INJECTION : PHPMYADMIN : http://1337day.com/exploit/5334';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, '/uploadify.php') !== false) {		
		if (strpos($par_Content, 'move_uploaded_file($tempFile,$targetFile') !== false) {
			$l_Vuln['id'] = 'AFU : UPLOADIFY : CVE: 2012-1153';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'com_adsmanager/controller.php') !== false) {		
		if (strpos($par_Content, 'move_uploaded_file($file[\'tmp_name\'], $tempPath.\'/\'.basename($file[') !== false) {
			$l_Vuln['id'] = 'AFU : https://revisium.com/ru/blog/adsmanager_afu.html';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'wp-content/plugins/wp-mobile-detector/resize.php') !== false) {		
		if (strpos($par_Content, 'file_put_contents($path, file_get_contents($_REQUEST[\'src\']));') !== false) {
			$l_Vuln['id'] = 'AFU : https://www.pluginvulnerabilities.com/2016/05/31/aribitrary-file-upload-vulnerability-in-wp-mobile-detector/';
			$l_Vuln['ndx'] = $par_Index;
			$g_Vulnerable[] = $l_Vuln;
			return true;
		}
		
		return false;
	}

	if (strpos($par_Filename, 'phpmailer.php') !== false) {		
		if (strpos($par_Content, 'PHPMailer') !== false) {
                        $l_Found = preg_match('~Version:\s*(\d+)\.(\d+)\.(\d+)~', $par_Content, $l_Match);

                        if ($l_Found) {
                           $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];

                           if ($l_Version < 2520) {
                              $l_Found = false;
                           }
                        }

                        if (!$l_Found) {

                           $l_Found = preg_match('~Version\s*=\s*\'(\d+)\.*(\d+)\.(\d+)~', $par_Content, $l_Match);
                           if ($l_Found) {
                              $l_Version = $l_Match[1] * 1000 + $l_Match[2] * 100 + $l_Match[3];
                              if ($l_Version < 5220) {
                                 $l_Found = false;
                              }
                           }
			}


		        if (!$l_Found) {
	   		   $l_Vuln['id'] = 'RCE : CVE-2016-10045, CVE-2016-10031';
			   $l_Vuln['ndx'] = $par_Index;
			   $g_Vulnerable[] = $l_Vuln;
			   return true;
                        }
		}
		
		return false;
	}




}

///////////////////////////////////////////////////////////////////////////
function QCR_GoScan($par_Offset)
{
	global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, 
		   $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList,
		   $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, 
		   $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, 
           $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, $g_KnownList,$g_Vulnerable;

    QCR_Debug('QCR_GoScan ' . $par_Offset);

	$i = 0;
	
	try {
		$s_file = new SplFileObject(QUEUE_FILENAME);
		$s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);

		foreach ($s_file as $l_Filename) {
			QCR_ScanFile($l_Filename, $i++);
		}
		
		unset($s_file);	
	}
	catch (Exception $e) { QCR_Debug( $e->getMessage() ); }
}

///////////////////////////////////////////////////////////////////////////
function QCR_ScanFile($l_Filename, $i = 0)
{
	global $g_IframerFragment, $g_Iframer, $g_Redirect, $g_Doorway, $g_EmptyLink, $g_Structure, $g_Counter, 
		   $g_HeuristicType, $g_HeuristicDetected, $g_TotalFolder, $g_TotalFiles, $g_WarningPHP, $g_AdwareList,
		   $g_CriticalPHP, $g_Phishing, $g_CriticalJS, $g_UrlIgnoreList, $g_CriticalJSFragment, $g_PHPCodeInside, $g_PHPCodeInsideFragment, 
		   $g_NotRead, $g_WarningPHPFragment, $g_WarningPHPSig, $g_BigFiles, $g_RedirectPHPFragment, $g_EmptyLinkSrc, $g_CriticalPHPSig, $g_CriticalPHPFragment, 
           $g_Base64Fragment, $g_UnixExec, $g_PhishingSigFragment, $g_PhishingFragment, $g_PhishingSig, $g_CriticalJSSig, $g_IframerFragment, $g_CMS, $defaults, $g_AdwareListFragment, 
           $g_KnownList,$g_Vulnerable, $g_CriticalFiles, $g_DeMapper;

	global $g_CRC;
	static $_files_and_ignored = 0;

			$l_CriticalDetected = false;
			$l_Stat = stat($l_Filename);

			if (substr($l_Filename, -1) == DIR_SEPARATOR) {
				// FOLDER
				$g_Structure['n'][$i] = $l_Filename;
				$g_TotalFolder++;
				printProgress($_files_and_ignored, $l_Filename);
				return;
			}

			QCR_Debug('Scan file ' . $l_Filename);
			printProgress(++$_files_and_ignored, $l_Filename);

     			// ignore itself
     			if ($l_Filename == __FILE__) {
     				return;
     			}

			// FILE
			if ((MAX_SIZE_TO_SCAN > 0 AND $l_Stat['size'] > MAX_SIZE_TO_SCAN) || ($l_Stat['size'] < 0))
			{
				$g_BigFiles[] = $i;

                                if (function_exists('aibolit_onBigFile')) { aibolit_onBigFile($l_Filename); }

				AddResult($l_Filename, $i);

		                $l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
                                if ((!AI_HOSTER) && in_array($l_Ext, $g_CriticalFiles)) {
				    $g_CriticalPHP[] = $i;
				    $g_CriticalPHPFragment[] = "BIG FILE. SKIPPED.";
				    $g_CriticalPHPSig[] = "big_1";
                                }
			}
			else
			{
				$g_TotalFiles++;

			$l_TSStartScan = microtime(true);

		$l_Ext = strtolower(pathinfo($l_Filename, PATHINFO_EXTENSION));
		if (filetype($l_Filename) == 'file') {
                   $l_Content = @file_get_contents($l_Filename);
		   if (SHORT_PHP_TAG) {
//                      $l_Content = preg_replace('|<\?\s|smiS', '<?php ', $l_Content); 
                   }

                   $l_Unwrapped = @php_strip_whitespace($l_Filename);
                }

		
                if ((($l_Content == '') || ($l_Unwrapped == '')) && ($l_Stat['size'] > 0)) {
                   $g_NotRead[] = $i;
                   if (function_exists('aibolit_onReadError')) { aibolit_onReadError($l_Filename, 'io'); }
                   AddResult('[io] ' . $l_Filename, $i);
                   return;
                }

				// unix executables
				if (strpos($l_Content, chr(127) . 'ELF') !== false) 
				{
			        	if (!in_array($l_Filename, $g_UnixExec)) {
                    				$g_UnixExec[] = $l_Filename;
					}

				        return;
                		}

				$g_CRC = _hash_($l_Unwrapped);

				$l_UnicodeContent = detect_utf_encoding($l_Content);
				//$l_Unwrapped = $l_Content;

				// check vulnerability in files
				$l_CriticalDetected = CheckVulnerability($l_Filename, $i, $l_Content);				

				if ($l_UnicodeContent !== false) {
       				   if (function_exists('iconv')) {
				      $l_Unwrapped = iconv($l_UnicodeContent, "CP1251//IGNORE", $l_Unwrapped);
//       			   if (function_exists('mb_convert_encoding')) {
//                                    $l_Unwrapped = mb_convert_encoding($l_Unwrapped, $l_UnicodeContent, "CP1251");
                                   } else {
                                      $g_NotRead[] = $i;
                                      if (function_exists('aibolit_onReadError')) { aibolit_onReadError($l_Filename, 'ec'); }
                                      AddResult('[ec] ' . $l_Filename, $i);
				   }
                                }

				// critical
				$g_SkipNextCheck = false;

                                $l_DeobfType = '';
				if (!AI_HOSTER) {
                                   $l_DeobfType = getObfuscateType($l_Unwrapped);
                                }

                                if ($l_DeobfType != '') {
                                   $l_Unwrapped = deobfuscate($l_Unwrapped);
				   $g_SkipNextCheck = checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType);
                                } else {
     				   if (DEBUG_MODE) {
				      stdOut("\n...... NOT OBFUSCATED\n");
				   }
				}

				$l_Unwrapped = UnwrapObfu($l_Unwrapped);
				
				if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Unwrapped, $l_Pos, $l_SigId))
				{
				        if ($l_Ext == 'js') {
 					   $g_CriticalJS[] = $i;
 					   $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
 					   $g_CriticalJSSig[] = $l_SigId;
                                        } else {
       					   $g_CriticalPHP[] = $i;
       					   $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
      					   $g_CriticalPHPSig[] = $l_SigId;
                                        }

					$g_SkipNextCheck = true;
				} else {
         				if ((!$g_SkipNextCheck) && CriticalPHP($l_Filename, $i, $l_Content, $l_Pos, $l_SigId))
         				{
					        if ($l_Ext == 'js') {
         					   $g_CriticalJS[] = $i;
         					   $g_CriticalJSFragment[] = getFragment($l_Content, $l_Pos);
         					   $g_CriticalJSSig[] = $l_SigId;
                                                } else {
               					   $g_CriticalPHP[] = $i;
               					   $g_CriticalPHPFragment[] = getFragment($l_Content, $l_Pos);
      						   $g_CriticalPHPSig[] = $l_SigId;
                                                }

         					$g_SkipNextCheck = true;
         				}
				}

				$l_TypeDe = 0;
			    if ((!$g_SkipNextCheck) && HeuristicChecker($l_Content, $l_TypeDe, $l_Filename)) {
					$g_HeuristicDetected[] = $i;
					$g_HeuristicType[] = $l_TypeDe;
					$l_CriticalDetected = true;
				}

				// critical JS
				if (!$g_SkipNextCheck) {
					$l_Pos = CriticalJS($l_Filename, $i, $l_Unwrapped, $l_SigId);
					if ($l_Pos !== false)
					{
					        if ($l_Ext == 'js') {
         					   $g_CriticalJS[] = $i;
         					   $g_CriticalJSFragment[] = getFragment($l_Unwrapped, $l_Pos);
         					   $g_CriticalJSSig[] = $l_SigId;
                                                } else {
               					   $g_CriticalPHP[] = $i;
               					   $g_CriticalPHPFragment[] = getFragment($l_Unwrapped, $l_Pos);
      						   $g_CriticalPHPSig[] = $l_SigId;
                                                }

						$g_SkipNextCheck = true;
					}
			    }

				// phishing
				if (!$g_SkipNextCheck) {
					$l_Pos = Phishing($l_Filename, $i, $l_Unwrapped, $l_SigId);
					if ($l_Pos === false) {
                                            $l_Pos = Phishing($l_Filename, $i, $l_Content, $l_SigId);
                                        }

					if ($l_Pos !== false)
					{
						$g_Phishing[] = $i;
						$g_PhishingFragment[] = getFragment($l_Unwrapped, $l_Pos);
						$g_PhishingSigFragment[] = $l_SigId;
						$g_SkipNextCheck = true;
					}
				}

			
			if (!$g_SkipNextCheck) {
				if (SCAN_ALL_FILES || stripos($l_Filename, 'index.'))
				{
					// check iframes
					if (preg_match_all('|<iframe[^>]+src.+?>|smi', $l_Unwrapped, $l_Found, PREG_SET_ORDER)) 
					{
						for ($kk = 0; $kk < count($l_Found); $kk++) {
						    $l_Pos = stripos($l_Found[$kk][0], 'http://');
						    $l_Pos = $l_Pos || stripos($l_Found[$kk][0], 'https://');
						    $l_Pos = $l_Pos || stripos($l_Found[$kk][0], 'ftp://');
							if  (($l_Pos !== false ) && (!knowUrl($l_Found[$kk][0]))) {
         						$g_Iframer[] = $i;
         						$g_IframerFragment[] = getFragment($l_Found[$kk][0], $l_Pos);
         						$l_CriticalDetected = true;
							}
						}
					}

					// check empty links
					if ((($defaults['report_mask'] & REPORT_MASK_SPAMLINKS) == REPORT_MASK_SPAMLINKS) &&
					   (preg_match_all('|<a[^>]+href([^>]+?)>(.*?)</a>|smi', $l_Unwrapped, $l_Found, PREG_SET_ORDER)))
					{
						for ($kk = 0; $kk < count($l_Found); $kk++) {
							if  ((stripos($l_Found[$kk][1], 'http://') !== false) &&
                                                            (trim(strip_tags($l_Found[$kk][2])) == '')) {

								$l_NeedToAdd = true;

							    if  ((stripos($l_Found[$kk][1], $defaults['site_url']) !== false)
                                                                 || knowUrl($l_Found[$kk][1])) {
										$l_NeedToAdd = false;
								}
								
								if ($l_NeedToAdd && (count($g_EmptyLink) < MAX_EXT_LINKS)) {
									$g_EmptyLink[] = $i;
									$g_EmptyLinkSrc[$i][] = substr($l_Found[$kk][0], 0, MAX_PREVIEW_LEN);
									$l_CriticalDetected = true;
								}
							}
						}
					}
				}

				// check for PHP code inside any type of file
				if (stripos($l_Ext, 'ph') === false)
				{
					$l_Pos = QCR_SearchPHP($l_Content);
					if ($l_Pos !== false)
					{
						$g_PHPCodeInside[] = $i;
						$g_PHPCodeInsideFragment[] = getFragment($l_Unwrapped, $l_Pos);
						$l_CriticalDetected = true;
					}
				}

				// htaccess
				if (stripos($l_Filename, '.htaccess'))
				{
				
					if (stripos($l_Content, 'index.php?name=$1') !== false ||
						stripos($l_Content, 'index.php?m=1') !== false
					)
					{
						$g_SuspDir[] = $i;
					}

					$l_HTAContent = preg_replace('|^\s*#.+$|m', '', $l_Content);

					$l_Pos = stripos($l_Content, 'auto_prepend_file');
					if ($l_Pos !== false) {
						$g_Redirect[] = $i;
						$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
						$l_CriticalDetected = true;
					}
					
					$l_Pos = stripos($l_Content, 'auto_append_file');
					if ($l_Pos !== false) {
						$g_Redirect[] = $i;
						$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
						$l_CriticalDetected = true;
					}

					$l_Pos = stripos($l_Content, '^(%2d|-)[^=]+$');
					if ($l_Pos !== false)
					{
						$g_Redirect[] = $i;
                        			$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
						$l_CriticalDetected = true;
					}

					if (!$l_CriticalDetected) {
						$l_Pos = stripos($l_Content, '%{HTTP_USER_AGENT}');
						if ($l_Pos !== false)
						{
							$g_Redirect[] = $i;
							$g_RedirectPHPFragment[] = getFragment($l_Content, $l_Pos);
							$l_CriticalDetected = true;
						}
					}

					if (!$l_CriticalDetected) {
						if (
							preg_match_all("|RewriteRule\s+.+?\s+http://(.+?)/.+\s+\[.*R=\d+.*\]|smi", $l_HTAContent, $l_Found, PREG_SET_ORDER)
						)
						{
							$l_Host = str_replace('www.', '', $_SERVER['HTTP_HOST']);
							for ($j = 0; $j < sizeof($l_Found); $j++)
							{
								$l_Found[$j][1] = str_replace('www.', '', $l_Found[$j][1]);
								if ($l_Found[$j][1] != $l_Host)
								{
									$g_Redirect[] = $i;
									$l_CriticalDetected = true;
									break;
								}
							}
						}
					}

					unset($l_HTAContent);
			    }
			

			    // warnings
				$l_Pos = '';
				
			    if (WarningPHP($l_Filename, $l_Unwrapped, $l_Pos, $l_SigId))
				{       
					$l_Prio = 1;
					if (strpos($l_Filename, '.ph') !== false) {
					   $l_Prio = 0;
					}
					
					$g_WarningPHP[$l_Prio][] = $i;
					$g_WarningPHPFragment[$l_Prio][] = getFragment($l_Unwrapped, $l_Pos);
					$g_WarningPHPSig[] = $l_SigId;

					$l_CriticalDetected = true;
				}
				

				// adware
				if (Adware($l_Filename, $l_Unwrapped, $l_Pos))
				{
					$g_AdwareList[] = $i;
					$g_AdwareListFragment[] = getFragment($l_Unwrapped, $l_Pos);
					$l_CriticalDetected = true;
				}

				// articles
				if (stripos($l_Filename, 'article_index'))
				{
					$g_AdwareList[] = $i;
					$l_CriticalDetected = true;
				}
			}
		} // end of if (!$g_SkipNextCheck) {
			
			unset($l_Unwrapped);
			unset($l_Content);
			
			//printProgress(++$_files_and_ignored, $l_Filename);

			$l_TSEndScan = microtime(true);
                        if ($l_TSEndScan - $l_TSStartScan >= 0.5) {
			   			   usleep(SCAN_DELAY * 1000);
                        }

			if ($g_SkipNextCheck || $l_CriticalDetected) {
				AddResult($l_Filename, $i);
			}
}

function AddResult($l_Filename, $i)
{
	global $g_Structure, $g_CRC;
	
	$l_Stat = stat($l_Filename);
	$g_Structure['n'][$i] = $l_Filename;
	$g_Structure['s'][$i] = $l_Stat['size'];
	$g_Structure['c'][$i] = $l_Stat['ctime'];
	$g_Structure['m'][$i] = $l_Stat['mtime'];
	$g_Structure['crc'][$i] = $g_CRC;
}

///////////////////////////////////////////////////////////////////////////
function WarningPHP($l_FN, $l_Content, &$l_Pos, &$l_SigId)
{
	   global $g_SusDB,$g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;

  $l_Res = false;

  if (AI_EXTRA_WARN) {
  	foreach ($g_SusDB as $l_Item) {
    	if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       	 	if (!CheckException($l_Content, $l_Found)) {
           	 	$l_Pos = $l_Found[0][1];
           	 	//$l_SigId = myCheckSum($l_Item);
           	 	$l_SigId = getSigId($l_Found);
           	 	return true;
       	 	}
    	}
  	}
  }

  if (AI_EXPERT < 2) {
    	foreach ($gXX_FlexDBShe as $l_Item) {
      		if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
             	$l_Pos = $l_Found[0][1];
           	    //$l_SigId = myCheckSum($l_Item);
           	    $l_SigId = getSigId($l_Found);
        	    return true;
	  		}
    	}

	}

    if (AI_EXPERT < 1) {
    	foreach ($gX_FlexDBShe as $l_Item) {
      		if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
             	$l_Pos = $l_Found[0][1];
           	 	//$l_SigId = myCheckSum($l_Item);
           	 	$l_SigId = getSigId($l_Found);
        	    return true;
	  		}
    	}

	    $l_Content_lo = strtolower($l_Content);

	    foreach ($gX_DBShe as $l_Item) {
	      $l_Pos = strpos($l_Content_lo, $l_Item);
	      if ($l_Pos !== false) {
	         $l_SigId = myCheckSum($l_Item);
	         return true;
	      }
		}
	}

}

///////////////////////////////////////////////////////////////////////////
function Adware($l_FN, $l_Content, &$l_Pos)
{
  global $g_AdwareSig;

  $l_Res = false;

foreach ($g_AdwareSig as $l_Item) {
    $offset = 0;
    while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           return true;
       }

       $offset = $l_Found[0][1] + 1;
    }
  }

  return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CheckException(&$l_Content, &$l_Found) {
  global $g_ExceptFlex, $gX_FlexDBShe, $gXX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment;
   $l_FoundStrPlus = substr($l_Content, max($l_Found[0][1] - 10, 0), 70);

   foreach ($g_ExceptFlex as $l_ExceptItem) {
      if (@preg_match('#' . $l_ExceptItem . '#smi', $l_FoundStrPlus, $l_Detected)) {
//         print("\n\nEXCEPTION FOUND\n[" . $l_ExceptItem .  "]\n" . $l_Content . "\n\n----------\n\n");
         return true;
      }
   }

   return false;
}

///////////////////////////////////////////////////////////////////////////
function Phishing($l_FN, $l_Index, $l_Content, &$l_SigId)
{
  global $g_PhishingSig, $g_PhishFiles, $g_PhishEntries;

  $l_Res = false;

  // need check file (by extension) ?
  $l_SkipCheck = SMART_SCAN;

if ($l_SkipCheck) {
  	foreach($g_PhishFiles as $l_Ext) {
  		  if (strpos($l_FN, $l_Ext) !== false) {
		  			$l_SkipCheck = false;
		  		  	break;
  	  	  }
  	  }
  }

  // need check file (by signatures) ?
  if ($l_SkipCheck && preg_match('~' . $g_PhishEntries . '~smiS', $l_Content, $l_Found)) {
	  $l_SkipCheck = false;
  }

  if ($l_SkipCheck && SMART_SCAN) {
      if (DEBUG_MODE) {
         echo "Skipped phs file, not critical.\n";
      }

	  return false;
  }


  foreach ($g_PhishingSig as $l_Item) {
    $offset = 0;
    while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
//           $l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "Phis: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return $l_Pos;
       }
       $offset = $l_Found[0][1] + 1;

    }
  }

  return $l_Res;
}

///////////////////////////////////////////////////////////////////////////
function CriticalJS($l_FN, $l_Index, $l_Content, &$l_SigId)
{
  global $g_JSVirSig, $gX_JSVirSig, $g_VirusFiles, $g_VirusEntries, $g_RegExpStat;

  $l_Res = false;
  
    // need check file (by extension) ?
    $l_SkipCheck = SMART_SCAN;
	
	if ($l_SkipCheck) {
       	   foreach($g_VirusFiles as $l_Ext) {
    		  if (strpos($l_FN, $l_Ext) !== false) {
  		  			$l_SkipCheck = false;
  		  		  	break;
    	  	  }
    	  }
	  }
  
    // need check file (by signatures) ?
    if ($l_SkipCheck && preg_match('~' . $g_VirusEntries . '~smiS', $l_Content, $l_Found)) {
  	  $l_SkipCheck = false;
    }
  
    if ($l_SkipCheck && SMART_SCAN) {
        if (DEBUG_MODE) {
           echo "Skipped js file, not critical.\n";
        }

  	  return false;
    }
  

  foreach ($g_JSVirSig as $l_Item) {
    $offset = 0;
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    while (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {

       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
//           $l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "JS: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return $l_Pos;
       }

       $offset = $l_Found[0][1] + 1;

    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }
//   if (pcre_error($l_FN, $l_Index)) {  }

  }

if (AI_EXPERT > 1) {
  foreach ($gX_JSVirSig as $l_Item) {
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    if (preg_match('#' . $l_Item . '#smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "JS PARA: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return $l_Pos;
       }
    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }

  }
}

  return $l_Res;
}

////////////////////////////////////////////////////////////////////////////
function pcre_error($par_FN, $par_Index) {
   global $g_NotRead, $g_Structure;

   $err = preg_last_error();
   if (($err == PREG_BACKTRACK_LIMIT_ERROR) || ($err == PREG_RECURSION_LIMIT_ERROR)) {
      if (!in_array($par_Index, $g_NotRead)) {
         if (function_exists('aibolit_onReadError')) { aibolit_onReadError($l_Filename, 're'); }
         $g_NotRead[] = $par_Index;
         AddResult('[re] ' . $par_FN, $par_Index);
      }
 
      return true;
   }

   return false;
}



////////////////////////////////////////////////////////////////////////////
define('SUSP_MTIME', 1); // suspicious mtime (greater than ctime)
define('SUSP_PERM', 2); // suspicious permissions 
define('SUSP_PHP_IN_UPLOAD', 3); // suspicious .php file in upload or image folder 

  function get_descr_heur($type) {
     switch ($type) {
	     case SUSP_MTIME: return AI_STR_077; 
	     case SUSP_PERM: return AI_STR_078;  
	     case SUSP_PHP_IN_UPLOAD: return AI_STR_079; 
	 }
	 
	 return "---";
  }

  ///////////////////////////////////////////////////////////////////////////
  function HeuristicChecker($l_Content, &$l_Type, $l_Filename) {
     $res = false;
	 
	 $l_Stat = stat($l_Filename);
	 // most likely changed by touch
	 if ($l_Stat['ctime'] < $l_Stat['mtime']) {
	     $l_Type = SUSP_MTIME;
		 return true;
	 }

	 	 
	 $l_Perm = fileperms($l_Filename) & 0777;
	 if (($l_Perm & 0400 != 0400) || // not readable by owner
		($l_Perm == 0000) ||
		($l_Perm == 0404) ||
		($l_Perm == 0505))
	 {
		 $l_Type = SUSP_PERM;
		 return true;
	 }

	 
     if ((strpos($l_Filename, '.ph')) && (
	     strpos($l_Filename, '/images/stories/') ||
	     //strpos($l_Filename, '/img/') ||
		 //strpos($l_Filename, '/images/') ||
	     //strpos($l_Filename, '/uploads/') ||
		 strpos($l_Filename, '/wp-content/upload/') 
	    )	    
	 ) {
		$l_Type = SUSP_PHP_IN_UPLOAD;
	 	return true;
	 }

     return false;
  }

///////////////////////////////////////////////////////////////////////////
function CriticalPHP($l_FN, $l_Index, $l_Content, &$l_Pos, &$l_SigId)
{
  global $g_ExceptFlex, $gXX_FlexDBShe, $gX_FlexDBShe, $g_FlexDBShe, $gX_DBShe, $g_DBShe, $g_Base64, $g_Base64Fragment,
  $g_CriticalFiles, $g_CriticalEntries, $g_RegExpStat;

  // need check file (by extension) ?
  $l_SkipCheck = SMART_SCAN;

  if ($l_SkipCheck) {
	  foreach($g_CriticalFiles as $l_Ext) {
  	  	if ((strpos($l_FN, $l_Ext) !== false) && (strpos($l_FN, '.js') === false)) {
		   $l_SkipCheck = false;
		   break;
  	  	}
  	  }
  }
  
  // need check file (by signatures) ?
  if ($l_SkipCheck && preg_match('~' . $g_CriticalEntries . '~smiS', $l_Content, $l_Found)) {
     $l_SkipCheck = false;
  }
  
  
  // if not critical - skip it 
  if ($l_SkipCheck && SMART_SCAN) {
      if (DEBUG_MODE) {
         echo "Skipped file, not critical.\n";
      }

	  return false;
  }

  foreach ($g_FlexDBShe as $l_Item) {
    $offset = 0;

    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    while (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE, $offset)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "CRIT 1: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return true;
       }

       $offset = $l_Found[0][1] + 1;

    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }

  }

if (AI_EXPERT > 0) {
  foreach ($gX_FlexDBShe as $l_Item) {
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "CRIT 3: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return true;
       }
    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }
  }
}

if (AI_EXPERT > 1) {
  foreach ($gXX_FlexDBShe as $l_Item) {
    if (DEBUG_PERFORMANCE) { 
       $stat_start = microtime(true);
    }

    if (preg_match('#' . $l_Item . '#smiS', $l_Content, $l_Found, PREG_OFFSET_CAPTURE)) {
       if (!CheckException($l_Content, $l_Found)) {
           $l_Pos = $l_Found[0][1];
           //$l_SigId = myCheckSum($l_Item);
           $l_SigId = getSigId($l_Found);

           if (DEBUG_MODE) {
              echo "CRIT 2: $l_FN matched [$l_Item] in $l_Pos\n";
           }

           return true;
       }
    }

    if (DEBUG_PERFORMANCE) { 
       $stat_stop = microtime(true);
       $g_RegExpStat[$l_Item] += $stat_stop - $stat_start;
    }

//   if (pcre_error($l_FN, $l_Index)) {  }
  }
}

  $l_Content_lo = strtolower($l_Content);

  foreach ($g_DBShe as $l_Item) {
    $l_Pos = strpos($l_Content_lo, $l_Item);
    if ($l_Pos !== false) {
       $l_SigId = myCheckSum($l_Item);

       if (DEBUG_MODE) {
          echo "CRIT 4: $l_FN matched [$l_Item] in $l_Pos\n";
       }

       return true;
    }
  }

if (AI_EXPERT > 0) {
  foreach ($gX_DBShe as $l_Item) {
    $l_Pos = strpos($l_Content_lo, $l_Item);
    if ($l_Pos !== false) {
       $l_SigId = myCheckSum($l_Item);

       if (DEBUG_MODE) {
          echo "CRIT 5: $l_FN matched [$l_Item] in $l_Pos\n";
       }

       return true;
    }
  }
}

if (AI_HOSTER) return false;

if (AI_EXPERT > 0) {
  if ((strpos($l_Content, 'GIF89') === 0) && (strpos($l_FN, '.php') !== false )) {
     $l_Pos = 0;

     if (DEBUG_MODE) {
          echo "CRIT 6: $l_FN matched [$l_Item] in $l_Pos\n";
     }

     return true;
  }
}

  // detect uploaders / droppers
if (AI_EXPERT > 1) {
  $l_Found = null;
  if (
     (filesize($l_FN) < 1024) &&
     (strpos($l_FN, '.ph') !== false) &&
     (
       (($l_Pos = strpos($l_Content, 'multipart/form-data')) > 0) || 
       (($l_Pos = strpos($l_Content, '$_FILE[') > 0)) ||
       (($l_Pos = strpos($l_Content, 'move_uploaded_file')) > 0) ||
       (preg_match('|\bcopy\s*\(|smi', $l_Content, $l_Found, PREG_OFFSET_CAPTURE))
     )
     ) {
       if ($l_Found != null) {
          $l_Pos = $l_Found[0][1];
       } 
     if (DEBUG_MODE) {
          echo "CRIT 7: $l_FN matched [$l_Item] in $l_Pos\n";
     }

     return true;
  }
}

  return false;
}

///////////////////////////////////////////////////////////////////////////
if (!isCli()) {
   header('Content-type: text/html; charset=utf-8');
}

if (!isCli()) {

  $l_PassOK = false;
  if (strlen(PASS) > 8) {
     $l_PassOK = true;   
  } 

  if ($l_PassOK && preg_match('|[0-9]|', PASS, $l_Found) && preg_match('|[A-Z]|', PASS, $l_Found) && preg_match('|[a-z]|', PASS, $l_Found) ) {
     $l_PassOK = true;   
  }
  
  if (!$l_PassOK) {  
    echo sprintf(AI_STR_009, generatePassword());
    exit;
  }

  if (isset($_GET['fn']) && ($_GET['ph'] == crc32(PASS))) {
     printFile();
     exit;
  }

  if ($_GET['p'] != PASS) {
    $generated_pass = generatePassword(); 
    echo sprintf(AI_STR_010, $generated_pass, $generated_pass);
    exit;
  }
}

if (!is_readable(ROOT_PATH)) {
  echo AI_STR_011;
  exit;
}

if (isCli()) {
	if (defined('REPORT_PATH') AND REPORT_PATH)
	{
		if (!is_writable(REPORT_PATH))
		{
			die2("\nCannot write report. Report dir " . REPORT_PATH . " is not writable.");
		}

		else if (!REPORT_FILE)
		{
			die2("\nCannot write report. Report filename is empty.");
		}

		else if (($file = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE) AND is_file($file) AND !is_writable($file))
		{
			die2("\nCannot write report. Report file '$file' exists but is not writable.");
		}
	}
}


// detect version CMS
$g_KnownCMS = array();
$tmp_cms = array();
$g_CmsListDetector = new CmsVersionDetector(ROOT_PATH);
$l_CmsDetectedNum = $g_CmsListDetector->getCmsNumber();
for ($tt = 0; $tt < $l_CmsDetectedNum; $tt++) {
    $g_CMS[] = $g_CmsListDetector->getCmsName($tt) . ' v' . makeSafeFn($g_CmsListDetector->getCmsVersion($tt));
    $tmp_cms[strtolower($g_CmsListDetector->getCmsName($tt))] = 1;
}

if (count($tmp_cms) > 0) {
   $g_KnownCMS = array_keys($tmp_cms);
   $len = count($g_KnownCMS);
   for ($i = 0; $i < $len; $i++) {
      if ($g_KnownCMS[$i] == strtolower(CMS_WORDPRESS)) $g_KnownCMS[] = 'wp';
      if ($g_KnownCMS[$i] == strtolower(CMS_WEBASYST)) $g_KnownCMS[] = 'shopscript';
      if ($g_KnownCMS[$i] == strtolower(CMS_IPB)) $g_KnownCMS[] = 'ipb';
      if ($g_KnownCMS[$i] == strtolower(CMS_DLE)) $g_KnownCMS[] = 'dle';
      if ($g_KnownCMS[$i] == strtolower(CMS_INSTANTCMS)) $g_KnownCMS[] = 'instantcms';
      if ($g_KnownCMS[$i] == strtolower(CMS_SHOPSCRIPT)) $g_KnownCMS[] = 'shopscript';
   }
}


$g_DirIgnoreList = array();
$g_IgnoreList = array();
$g_UrlIgnoreList = array();
$g_KnownList = array();

$l_IgnoreFilename = $g_AiBolitAbsolutePath . '/.aignore';
$l_DirIgnoreFilename = $g_AiBolitAbsolutePath . '/.adirignore';
$l_UrlIgnoreFilename = $g_AiBolitAbsolutePath . '/.aurlignore';

if (file_exists($l_IgnoreFilename)) {
    $l_IgnoreListRaw = file($l_IgnoreFilename);
    for ($i = 0; $i < count($l_IgnoreListRaw); $i++) 
    {
    	$g_IgnoreList[] = explode("\t", trim($l_IgnoreListRaw[$i]));
    }
    unset($l_IgnoreListRaw);
}

if (file_exists($l_DirIgnoreFilename)) {
    $g_DirIgnoreList = file($l_DirIgnoreFilename);
	
	for ($i = 0; $i < count($g_DirIgnoreList); $i++) {
		$g_DirIgnoreList[$i] = trim($g_DirIgnoreList[$i]);
	}
}

if (file_exists($l_UrlIgnoreFilename)) {
    $g_UrlIgnoreList = file($l_UrlIgnoreFilename);
	
	for ($i = 0; $i < count($g_UrlIgnoreList); $i++) {
		$g_UrlIgnoreList[$i] = trim($g_UrlIgnoreList[$i]);
	}
}


$l_SkipMask = array(
            '/template_\w{32}.css',
            '/cache/templates/.{1,150}\.tpl\.php',
	    '/system/cache/templates_c/\w{1,40}\.php',
	    '/assets/cache/rss/\w{1,60}',
            '/cache/minify/minify_\w{32}',
            '/cache/page/\w{32}\.php',
            '/cache/object/\w{1,10}/\w{1,10}/\w{1,10}/\w{32}\.php',
            '/cache/wp-cache-\d{32}\.php',
            '/cache/page/\w{32}\.php_expire',
	    '/cache/page/\w{32}-cache-page-\w{32}\.php',
	    '\w{32}-cache-com_content-\w{32}\.php',
	    '\w{32}-cache-mod_custom-\w{32}\.php',
	    '\w{32}-cache-mod_templates-\w{32}\.php',
            '\w{32}-cache-_system-\w{32}\.php',
            '/cache/twig/\w{1,32}/\d+/\w{1,100}\.php', 
            '/autoptimize/js/autoptimize_\w{32}\.js',
            '/bitrix/cache/\w{32}\.php',
            '/bitrix/cache/.+/\w{32}\.php',
            '/bitrix/cache/iblock_find/',
            '/bitrix/managed_cache/MYSQL/user_option/[^/]+/',
            '/bitrix/cache/s1/bitrix/catalog\.section/',
            '/bitrix/cache/s1/bitrix/catalog\.element/',
            '/bitrix/cache/s1/bitrix/menu/',
            '/catalog.element/[^/]+/[^/]+/\w{32}\.php',
            '/bitrix/managed\_cache/.*/\.\w{32}\.php',
            '/core/cache/mgr/smarty/default/.{1,100}\.tpl\.php',
            '/core/cache/resource/web/resources/[0-9]{1,50}\.cache\.php',
            '/smarty/compiled/SC/.*/%%.*\.php',
            '/smarty/.{1,150}\.tpl\.php',
            '/smarty/compile/.{1,150}\.tpl\.cache\.php',
            '/files/templates_c/.{1,150}\.html\.php',
            '/uploads/javascript_global/.{1,150}\.js',
            '/assets/cache/rss/\w{32}',
	    '/assets/cache/docid_\d+_\w{32}\.pageCache\.php',
            '/t3-assets/dev/t3/.*-cache-\w{1,20}-.{1,150}\.php',
	    '/t3-assets/js/js-\w{1,30}\.js',
            '/temp/cache/SC/.*/\.cache\..*\.php',
            '/tmp/sess\_\w{32}$',
            '/assets/cache/docid\_.*\.pageCache\.php',
            '/stat/usage\_\w+\.html',
            '/stat/site\_\w+\.html',
            '/gallery/item/list/\w+\.cache\.php',
            '/core/cache/registry/.*/ext-.*\.php',
            '/core/cache/resource/shk\_/\w+\.cache\.php',
            '/webstat/awstats.*\.txt',
            '/awstats/awstats.*\.txt',
            '/awstats/.{1,80}\.pl',
            '/awstats/.{1,80}\.html',
            '/inc/min/styles_\w+\.min\.css',
            '/inc/min/styles_\w+\.min\.js',
            '/logs/error\_log\..*',
            '/logs/xferlog\..*',
            '/logs/access_log\..*',
            '/logs/cron\..*',
            '/logs/exceptions/.+\.log$',
            '/hyper-cache/[^/]+/[^/]+/[^/]+/index\.html',
            '/mail/new/[^,]+,S=[^,]+,W=.+',
            '/mail/new/[^,]=,S=.+',
            '/application/logs/\d+/\d+/\d+\.php',
            '/sites/default/files/js/js_\w{32}\.js',
            '/yt-assets/\w{32}\.css',
);

$l_SkipSample = array();

if (SMART_SCAN) {
   $g_DirIgnoreList = array_merge($g_DirIgnoreList, $l_SkipMask);
}

QCR_Debug();

// Load custom signatures

try {
	$s_file = new SplFileObject($g_AiBolitAbsolutePath."/ai-bolit.sig");
	$s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);
	foreach ($s_file as $line) {
		$g_FlexDBShe[] = preg_replace('~\G(?:[^#\\\\]+|\\\\.)*+\K#~', '\\#', $line); // escaping #
	}
	stdOut("Loaded " . $s_file->key() . " signatures from ai-bolit.sig");
	$s_file = null; // file handler is closed
} catch (Exception $e) { QCR_Debug( "Import ai-bolit.sig " . $e->getMessage() ); }

QCR_Debug();

	$defaults['skip_ext'] = strtolower(trim($defaults['skip_ext']));
         if ($defaults['skip_ext'] != '') {
	    $g_IgnoredExt = explode(',', $defaults['skip_ext']);
	    for ($i = 0; $i < count($g_IgnoredExt); $i++) {
                $g_IgnoredExt[$i] = trim($g_IgnoredExt[$i]);
             }

	    QCR_Debug('Skip files with extensions: ' . implode(',', $g_IgnoredExt));
	    stdOut('Skip extensions: ' . implode(',', $g_IgnoredExt));
         } 

// scan single file
if (defined('SCAN_FILE')) {
   if (file_exists(SCAN_FILE) && is_file(SCAN_FILE) && is_readable(SCAN_FILE)) {
       stdOut("Start scanning file '" . SCAN_FILE . "'.");
       QCR_ScanFile(SCAN_FILE); 
   } else { 
       stdOut("Error:" . SCAN_FILE . " either is not a file or readable");
   }
} else {
	if (isset($_GET['2check'])) {
		$options['with-2check'] = 1;
	}
   
   // scan list of files from file
   if (!(ICHECK || IMAKE) && isset($options['with-2check']) && file_exists(DOUBLECHECK_FILE)) {
      stdOut("Start scanning the list from '" . DOUBLECHECK_FILE . "'.\n");
      $lines = file(DOUBLECHECK_FILE);
      for ($i = 0, $size = count($lines); $i < $size; $i++) {
         $lines[$i] = trim($lines[$i]);
         if (empty($lines[$i])) unset($lines[$i]);
      }
      /* skip first line with <?php die("Forbidden"); ?> */
      unset($lines[0]);
      $g_FoundTotalFiles = count($lines);
      $i = 1;
      foreach ($lines as $l_FN) {
         is_dir($l_FN) && $g_TotalFolder++;
         printProgress( $i++, $l_FN);
         $BOOL_RESULT = true; // display disable
         is_file($l_FN) && QCR_ScanFile($l_FN, $i);
         $BOOL_RESULT = false; // display enable
      }

      $g_FoundTotalDirs = $g_TotalFolder;
      $g_FoundTotalFiles = $g_TotalFiles;

   } else {
      // scan whole file system
      stdOut("Start scanning '" . ROOT_PATH . "'.\n");
      
      file_exists(QUEUE_FILENAME) && unlink(QUEUE_FILENAME);
      if (ICHECK || IMAKE) {
      // INTEGRITY CHECK
        IMAKE and unlink(INTEGRITY_DB_FILE);
        ICHECK and load_integrity_db();
        QCR_IntegrityCheck(ROOT_PATH);
        stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
        if (IMAKE) exit(0);
        if (ICHECK) {
            $i = $g_Counter;
            $g_CRC = 0;
            $changes = array();
            $ref =& $g_IntegrityDB;
            foreach ($g_IntegrityDB as $l_FileName => $type) {
                unset($g_IntegrityDB[$l_FileName]);
                $l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
                if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                    continue;
                }
                for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
                    if (($g_DirIgnoreList[$dr] != '') && preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
                        continue 2;
                    }
                }
                $type = in_array($type, array('added', 'modified')) ? $type : 'deleted';
                $type .= substr($l_FileName, -1) == '/' ? 'Dirs' : 'Files';
                $changes[$type][] = ++$i;
                AddResult($l_FileName, $i);
            }
            $g_FoundTotalFiles = count($changes['addedFiles']) + count($changes['modifiedFiles']);
            stdOut("Found changes " . count($changes['modifiedFiles']) . " files and added " . count($changes['addedFiles']) . " files.");
        }
        
      } else {
      QCR_ScanDirectories(ROOT_PATH);
      stdOut("Found $g_FoundTotalFiles files in $g_FoundTotalDirs directories.");
      }

      QCR_Debug();
      stdOut(str_repeat(' ', 160),false);
      QCR_GoScan(0);
      unlink(QUEUE_FILENAME);
      if (defined('PROGRESS_LOG_FILE') && file_exists(PROGRESS_LOG_FILE)) @unlink(PROGRESS_LOG_FILE);
   }
}

QCR_Debug();

if (true) {
   $g_HeuristicDetected = array();
   $g_Iframer = array();
   $g_Base64 = array();
}


// whitelist

$snum = 0;
$list = check_whitelist($g_Structure['crc'], $snum);

foreach (array('g_CriticalPHP', 'g_CriticalJS', 'g_Iframer', 'g_Base64', 'g_Phishing', 'g_AdwareList', 'g_Redirect') as $p) {
	if (empty($$p)) continue;
	
	$p_Fragment = $p . "Fragment";
	$p_Sig = $p . "Sig";
	if ($p == 'g_Redirect') $p_Fragment = $p . "PHPFragment";
	if ($p == 'g_Phishing') $p_Sig = $p . "SigFragment";

	$count = count($$p);
	for ($i = 0; $i < $count; $i++) {
		$id = "{${$p}[$i]}";
		if (in_array($g_Structure['crc'][$id], $list)) {
			unset($GLOBALS[$p][$i]);
			unset($GLOBALS[$p_Sig][$i]);
			unset($GLOBALS[$p_Fragment][$i]);
		}
	}

	$$p = array_values($$p);
	$$p_Fragment = array_values($$p_Fragment);
	if (!empty($$p_Sig)) $$p_Sig = array_values($$p_Sig);
}


////////////////////////////////////////////////////////////////////////////
if (AI_HOSTER) {
   $g_IframerFragment = array();
   $g_Iframer = array();
   $g_Redirect = array();
   $g_Doorway = array();
   $g_EmptyLink = array();
   $g_HeuristicType = array();
   $g_HeuristicDetected = array();
   $g_WarningPHP = array();
   $g_AdwareList = array();
   $g_Phishing = array(); 
   $g_PHPCodeInside = array();
   $g_PHPCodeInsideFragment = array();
   $g_NotRead = array();
   $g_WarningPHPFragment = array();
   $g_WarningPHPSig = array();
   $g_BigFiles = array();
   $g_RedirectPHPFragment = array();
   $g_EmptyLinkSrc = array();
   $g_Base64Fragment = array();
   $g_UnixExec = array();
   $g_PhishingSigFragment = array();
   $g_PhishingFragment = array();
   $g_PhishingSig = array();
   $g_IframerFragment = array();
   $g_CMS = array();
   $g_AdwareListFragment = array(); 
   $g_Vulnerable = array();
}

 if (BOOL_RESULT && (!defined('NEED_REPORT'))) {
  if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_Base64) > 0) OR  (count($g_Iframer) > 0) OR  (count($g_UnixExec) > 0))
  {
  echo "1\n";
  exit(0);
  }
 }
////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@SERVICE_INFO@@", htmlspecialchars("[" . $int_enc . "][" . $snum . "]"), $l_Template);

$l_Template = str_replace("@@PATH_URL@@", (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : $g_AddPrefix . str_replace($g_NoPrefix, '', addSlash(ROOT_PATH))), $l_Template);

$time_taken = seconds2Human(microtime(true) - START_TIME);

$l_Template = str_replace("@@SCANNED@@", sprintf(AI_STR_013, $g_TotalFolder, $g_TotalFiles), $l_Template);

$l_ShowOffer = false;

stdOut("\nBuilding report [ mode = " . AI_EXPERT . " ]\n");

//stdOut("\nLoaded signatures: " . count($g_FlexDBShe) . " / " . count($g_JSVirSig) . "\n");

////////////////////////////////////////////////////////////////////////////
// save 
if (!(ICHECK || IMAKE))
if (isset($options['with-2check']) || isset($options['quarantine']))
if ((count($g_CriticalPHP) > 0) OR (count($g_CriticalJS) > 0) OR (count($g_Base64) > 0) OR 
   (count($g_Iframer) > 0) OR  (count($g_UnixExec))) 
{
  if (!file_exists(DOUBLECHECK_FILE)) {	  
      if ($l_FH = fopen(DOUBLECHECK_FILE, 'w')) {
         fputs($l_FH, '<?php die("Forbidden"); ?>' . "\n");

         $l_CurrPath = dirname(__FILE__);
		 
		 if (!isset($g_CriticalPHP)) { $g_CriticalPHP = array(); }
		 if (!isset($g_CriticalJS)) { $g_CriticalJS = array(); }
		 if (!isset($g_Iframer)) { $g_Iframer = array(); }
		 if (!isset($g_Base64)) { $g_Base64 = array(); }
		 if (!isset($g_Phishing)) { $g_Phishing = array(); }
		 if (!isset($g_AdwareList)) { $g_AdwareList = array(); }
		 if (!isset($g_Redirect)) { $g_Redirect = array(); }
		 
         $tmpIndex = array_merge($g_CriticalPHP, $g_CriticalJS, $g_Phishing, $g_Base64, $g_Iframer, $g_AdwareList, $g_Redirect);
         $tmpIndex = array_values(array_unique($tmpIndex));

         for ($i = 0; $i < count($tmpIndex); $i++) {
             $tmpIndex[$i] = str_replace($l_CurrPath, '.', $g_Structure['n'][$tmpIndex[$i]]);
         }

         for ($i = 0; $i < count($g_UnixExec); $i++) {
             $tmpIndex[] = str_replace($l_CurrPath, '.', $g_UnixExec[$i]);
         }

         $tmpIndex = array_values(array_unique($tmpIndex));

         for ($i = 0; $i < count($tmpIndex); $i++) {
             fputs($l_FH, $tmpIndex[$i] . "\n");
         }

         fclose($l_FH);
      } else {
         stdOut("Error! Cannot create " . DOUBLECHECK_FILE);
      }      
  } else {
      stdOut(DOUBLECHECK_FILE . ' already exists.');
      if (AI_STR_044 != '') $l_Result .= '<div class="rep">' . AI_STR_044 . '</div>';
  }
 
}

////////////////////////////////////////////////////////////////////////////

$l_Summary = '<div class="title">' . AI_STR_074 . '</div>';
$l_Summary .= '<table cellspacing=0 border=0>';

if (count($g_Redirect) > 0) {
   $l_Summary .= makeSummary(AI_STR_059, count($g_Redirect), "crit");
}

if (count($g_CriticalPHP) > 0) {
   $l_Summary .= makeSummary(AI_STR_060, count($g_CriticalPHP), "crit");
}

if (count($g_CriticalJS) > 0) {
   $l_Summary .= makeSummary(AI_STR_061, count($g_CriticalJS), "crit");
}

if (count($g_Phishing) > 0) {
   $l_Summary .= makeSummary(AI_STR_062, count($g_Phishing), "crit");
}

if (count($g_UnixExec) > 0) {
   $l_Summary .= makeSummary(AI_STR_063, count($g_UnixExec), (AI_EXPERT > 1 ? 'crit' : 'warn'));
}

if (count($g_Iframer) > 0) {
   $l_Summary .= makeSummary(AI_STR_064, count($g_Iframer), "crit");
}

if (count($g_NotRead) > 0) {
   $l_Summary .= makeSummary(AI_STR_066, count($g_NotRead), "crit");
}

if (count($g_Base64) > 0) {
   $l_Summary .= makeSummary(AI_STR_067, count($g_Base64), (AI_EXPERT > 1 ? 'crit' : 'warn'));
}

if (count($g_BigFiles) > 0) {
   $l_Summary .= makeSummary(AI_STR_065, count($g_BigFiles), "warn");
}

if (count($g_HeuristicDetected) > 0) {
   $l_Summary .= makeSummary(AI_STR_068, count($g_HeuristicDetected), "warn");
}

if (count($g_SymLinks) > 0) {
   $l_Summary .= makeSummary(AI_STR_069, count($g_SymLinks), "warn");
}

if (count($g_HiddenFiles) > 0) {
   $l_Summary .= makeSummary(AI_STR_070, count($g_HiddenFiles), "warn");
}

if (count($g_AdwareList) > 0) {
   $l_Summary .= makeSummary(AI_STR_072, count($g_AdwareList), "warn");
}

if (count($g_EmptyLink) > 0) {
   $l_Summary .= makeSummary(AI_STR_073, count($g_EmptyLink), "warn");
}

 $l_Summary .= "</table>";

$l_ArraySummary = array();
$l_ArraySummary["redirect"] = count($g_Redirect);
$l_ArraySummary["critical_php"] = count($g_CriticalPHP);
$l_ArraySummary["critical_js"] = count($g_CriticalJS);
$l_ArraySummary["phishing"] = count($g_Phishing);
$l_ArraySummary["unix_exec"] = count($g_UnixExec);
$l_ArraySummary["iframes"] = count($g_Iframer);
$l_ArraySummary["not_read"] = count($g_NotRead);
$l_ArraySummary["base64"] = count($g_Base64);
$l_ArraySummary["heuristics"] = count($g_HeuristicDetected);
$l_ArraySummary["symlinks"] = count($g_SymLinks);
$l_ArraySummary["big_files_skipped"] = count($g_BigFiles);

 if (function_exists('json_encode')) { $l_Summary .= "<!--[json]" . json_encode($l_ArraySummary) . "[/json]-->"; }

 $l_Summary .= "<div class=details style=\"margin: 20px 20px 20px 0\">" . AI_STR_080 . "</div>\n";

 $l_Template = str_replace("@@SUMMARY@@", $l_Summary, $l_Template);


 $l_Result .= AI_STR_015;
 
 $l_Template = str_replace("@@VERSION@@", AI_VERSION, $l_Template);
 
////////////////////////////////////////////////////////////////////////////



if (function_exists("gethostname") && is_callable("gethostname")) {
  $l_HostName = gethostname();
} else {
  $l_HostName = '???';
}

$l_PlainResult = "# Malware list detected by AI-Bolit (https://revisium.com/ai/) on " . date("d/m/Y H:i:s", time()) . " " . $l_HostName .  "\n\n";

$l_RawReport = array();

if (!AI_HOSTER) {
   stdOut("Building list of vulnerable scripts " . count($g_Vulnerable));

   if (count($g_Vulnerable) > 0) {
       $l_Result .= '<div class="note_vir">' . AI_STR_081 . ' (' . count($g_Vulnerable) . ')</div><div class="crit">';
    	foreach ($g_Vulnerable as $l_Item) {
   	    $l_Result .= '<li>' . makeSafeFn($g_Structure['n'][$l_Item['ndx']], true) . ' - ' . $l_Item['id'] . '</li>';
               $l_PlainResult .= '[VULNERABILITY] ' . replacePathArray($g_Structure['n'][$l_Item['ndx']]) . ' - ' . $l_Item['id'] . "\n";
    	}
   	
     $l_Result .= '</div><p>' . PHP_EOL;
     $l_PlainResult .= "\n";
   }
}


stdOut("Building list of shells " . count($g_CriticalPHP));

$l_RawReport['vulners'] = getRawJsonVuln($g_Vulnerable);

if (count($g_CriticalPHP) > 0) {
  $g_CriticalPHP = array_slice($g_CriticalPHP, 0, 15000);
  $l_RawReport['php_malware'] = getRawJson($g_CriticalPHP, $g_CriticalPHPFragment, $g_CriticalPHPSig);
  $l_Result .= '<div class="note_vir">' . AI_STR_016 . ' (' . count($g_CriticalPHP) . ')</div><div class="crit">';
  $l_Result .= printList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit');
  $l_PlainResult .= '[SERVER MALWARE]' . "\n" . printPlainList($g_CriticalPHP, $g_CriticalPHPFragment, true, $g_CriticalPHPSig, 'table_crit') . "\n";
  $l_Result .= '</div>' . PHP_EOL;

  $l_ShowOffer = true;
} else {
  $l_Result .= '<div class="ok"><b>' . AI_STR_017. '</b></div>';
}

stdOut("Building list of js " . count($g_CriticalJS));

if (count($g_CriticalJS) > 0) {
  $g_CriticalJS = array_slice($g_CriticalJS, 0, 15000);
  $l_RawReport['js_malware'] = getRawJson($g_CriticalJS, $g_CriticalJSFragment, $g_CriticalJSSig);
  $l_Result .= '<div class="note_vir">' . AI_STR_018 . ' (' . count($g_CriticalJS) . ')</div><div class="crit">';
  $l_Result .= printList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir');
  $l_PlainResult .= '[CLIENT MALWARE / JS]'  . "\n" . printPlainList($g_CriticalJS, $g_CriticalJSFragment, true, $g_CriticalJSSig, 'table_vir') . "\n";
  $l_Result .= "</div>" . PHP_EOL;

  $l_ShowOffer = true;
}

if (!AI_HOSTER) {
   stdOut("Building phishing pages " . count($g_Phishing));

   if (count($g_Phishing) > 0) {
     $l_RawReport['phishing'] = getRawJson($g_Phishing, $g_PhishingFragment, $g_PhishingSigFragment);
     $l_Result .= '<div class="note_vir">' . AI_STR_058 . ' (' . count($g_Phishing) . ')</div><div class="crit">';
     $l_Result .= printList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir');
     $l_PlainResult .= '[PHISHING]'  . "\n" . printPlainList($g_Phishing, $g_PhishingFragment, true, $g_PhishingSigFragment, 'table_vir') . "\n";
     $l_Result .= "</div>". PHP_EOL;

     $l_ShowOffer = true;
   }

   stdOut("Building list of iframes " . count($g_Iframer));

   if (count($g_Iframer) > 0) {
     $l_RawReport['iframer'] = getRawJson($g_Iframer, $g_IframerFragment);
     $l_ShowOffer = true;
     $l_Result .= '<div class="note_vir">' . AI_STR_021 . ' (' . count($g_Iframer) . ')</div><div class="crit">';
     $l_Result .= printList($g_Iframer, $g_IframerFragment, true);
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of base64s " . count($g_Base64));

   if (count($g_Base64) > 0) {
     $l_RawReport['warn_enc'] = getRawJson($g_Base64, $g_Base64Fragment);
     if (AI_EXPERT > 1) $l_ShowOffer = true;
     
     $l_Result .= '<div class="note_' . (AI_EXPERT > 1 ? 'vir' : 'warn') . '">' . AI_STR_020 . ' (' . count($g_Base64) . ')</div><div class="' . (AI_EXPERT > 1 ? 'crit' : 'warn') . '">';
     $l_Result .= printList($g_Base64, $g_Base64Fragment, true);
     $l_PlainResult .= '[ENCODED / SUSP_EXT]' . "\n" . printPlainList($g_Base64, $g_Base64Fragment, true) . "\n";
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of redirects " . count($g_Redirect));
   if (count($g_Redirect) > 0) {
     $l_RawReport['redirect'] = getRawJson($g_Redirect, $g_RedirectPHPFragment);
     $l_ShowOffer = true;
     $l_Result .= '<div class="note_vir">' . AI_STR_027 . ' (' . count($g_Redirect) . ')</div><div class="crit">';
     $l_Result .= printList($g_Redirect, $g_RedirectPHPFragment, true);
     $l_Result .= "</div>" . PHP_EOL;
   }


   stdOut("Building list of unread files " . count($g_NotRead));

   if (count($g_NotRead) > 0) {
     $g_NotRead = array_slice($g_NotRead, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['not_read'] = $g_NotRead;
     $l_Result .= '<div class="note_vir">' . AI_STR_030 . ' (' . count($g_NotRead) . ')</div><div class="crit">';
     $l_Result .= printList($g_NotRead);
     $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
     $l_PlainResult .= '[SCAN ERROR / SKIPPED]' . "\n" . printPlainList($g_NotRead) . "\n\n";
   }

   stdOut("Building list of symlinks " . count($g_SymLinks));

   if (count($g_SymLinks) > 0) {
     $g_SymLinks = array_slice($g_SymLinks, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['sym_links'] = $g_SymLinks;
     $l_Result .= '<div class="note_vir">' . AI_STR_022 . ' (' . count($g_SymLinks) . ')</div><div class="crit">';
     $l_Result .= nl2br(makeSafeFn(implode("\n", $g_SymLinks), true));
     $l_Result .= "</div><div class=\"spacer\"></div>";
   }

   stdOut("Building list of unix executables and odd scripts " . count($g_UnixExec));

   if (count($g_UnixExec) > 0) {
     $g_UnixExec = array_slice($g_UnixExec, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['unix_exec'] = $g_UnixExec;
     $l_Result .= '<div class="note_' . (AI_EXPERT > 1 ? 'vir' : 'warn') . '">' . AI_STR_019 . ' (' . count($g_UnixExec) . ')</div><div class="' . (AI_EXPERT > 1 ? 'crit' : 'warn') . '">';
     $l_Result .= nl2br(makeSafeFn(implode("\n", $g_UnixExec), true));
     $l_PlainResult .= '[UNIX EXEC]' . "\n" . implode("\n", replacePathArray($g_UnixExec)) . "\n\n";
     $l_Result .= "</div>" . PHP_EOL;

     if (AI_EXPERT > 1) $l_ShowOffer = true;
   }
}
////////////////////////////////////
if (!AI_HOSTER) {
   $l_WarningsNum = count($g_HeuristicDetected) + count($g_HiddenFiles) + count($g_BigFiles) + count($g_PHPCodeInside) + count($g_AdwareList) + count($g_EmptyLink) + count($g_Doorway) + (count($g_WarningPHP[0]) + count($g_WarningPHP[1]) + count($g_SkippedFolders));

   if ($l_WarningsNum > 0) {
   	$l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_026 . "</div>";
   }

   stdOut("Building list of links/adware " . count($g_AdwareList));

   if (count($g_AdwareList) > 0) {
     $l_RawReport['adware'] = getRawJson($g_AdwareList, $g_AdwareListFragment);
     $l_Result .= '<div class="note_warn">' . AI_STR_029 . '</div><div class="warn">';
     $l_Result .= printList($g_AdwareList, $g_AdwareListFragment, true);
     $l_PlainResult .= '[ADWARE]' . "\n" . printPlainList($g_AdwareList, $g_AdwareListFragment, true) . "\n";
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of heuristics " . count($g_HeuristicDetected));

   if (count($g_HeuristicDetected) > 0) {
     $l_RawReport['heuristic'] = $g_HeuristicDetected;
     $l_Result .= '<div class="note_warn">' . AI_STR_052 . ' (' . count($g_HeuristicDetected) . ')</div><div class="warn">';
     for ($i = 0; $i < count($g_HeuristicDetected); $i++) {
   	   $l_Result .= '<li>' . makeSafeFn($g_Structure['n'][$g_HeuristicDetected[$i]], true) . ' (' . get_descr_heur($g_HeuristicType[$i]) . ')</li>';
     }
     
     $l_Result .= '</ul></div><div class=\"spacer\"></div>' . PHP_EOL;
   }

   stdOut("Building list of hidden files " . count($g_HiddenFiles));
   if (count($g_HiddenFiles) > 0) {
     $g_HiddenFiles = array_slice($g_HiddenFiles, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['hidden'] = $g_HiddenFiles;
     $l_Result .= '<div class="note_warn">' . AI_STR_023 . ' (' . count($g_HiddenFiles) . ')</div><div class="warn">';
     $l_Result .= nl2br(makeSafeFn(implode("\n", $g_HiddenFiles), true));
     $l_Result .= "</div><div class=\"spacer\"></div>" . PHP_EOL;
     $l_PlainResult .= '[HIDDEN]' . "\n" . implode("\n", replacePathArray($g_HiddenFiles)) . "\n\n";
   }

   stdOut("Building list of bigfiles " . count($g_BigFiles));
   $max_size_to_scan = getBytes(MAX_SIZE_TO_SCAN);
   $max_size_to_scan = $max_size_to_scan > 0 ? $max_size_to_scan : getBytes('1m');

   if (count($g_BigFiles) > 0) {
     $g_BigFiles = array_slice($g_BigFiles, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['big_files'] = getRawJson($g_BigFiles);
     $l_Result .= "<div class=\"note_warn\">" . sprintf(AI_STR_038, bytes2Human($max_size_to_scan)) . '</div><div class="warn">';
     $l_Result .= printList($g_BigFiles);
     $l_Result .= "</div>";
     $l_PlainResult .= '[BIG FILES / SKIPPED]' . "\n" . printPlainList($g_BigFiles) . "\n\n";
   } 

   stdOut("Building list of php inj " . count($g_PHPCodeInside));

   if ((count($g_PHPCodeInside) > 0) && (($defaults['report_mask'] & REPORT_MASK_PHPSIGN) == REPORT_MASK_PHPSIGN)) {
     $l_Result .= '<div class="note_warn">' . AI_STR_028 . '</div><div class="warn">';
     $l_Result .= printList($g_PHPCodeInside, $g_PHPCodeInsideFragment, true);
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of empty links " . count($g_EmptyLink));
   if (count($g_EmptyLink) > 0) {
     $g_EmptyLink = array_slice($g_EmptyLink, 0, AIBOLIT_MAX_NUMBER);
     $l_Result .= '<div class="note_warn">' . AI_STR_031 . '</div><div class="warn">';
     $l_Result .= printList($g_EmptyLink, '', true);

     $l_Result .= AI_STR_032 . '<br/>';
     
     if (count($g_EmptyLink) == MAX_EXT_LINKS) {
         $l_Result .= '(' . AI_STR_033 . MAX_EXT_LINKS . ')<br/>';
       }
      
     for ($i = 0; $i < count($g_EmptyLink); $i++) {
   	$l_Idx = $g_EmptyLink[$i];
       for ($j = 0; $j < count($g_EmptyLinkSrc[$l_Idx]); $j++) {
         $l_Result .= '<span class="details">' . makeSafeFn($g_Structure['n'][$g_EmptyLink[$i]], true) . ' &rarr; ' . htmlspecialchars($g_EmptyLinkSrc[$l_Idx][$j]) . '</span><br/>';
   	}
     }

     $l_Result .= "</div>";

   }

   stdOut("Building list of doorways " . count($g_Doorway));

   if ((count($g_Doorway) > 0) && (($defaults['report_mask'] & REPORT_MASK_DOORWAYS) == REPORT_MASK_DOORWAYS)) {
     $g_Doorway = array_slice($g_Doorway, 0, AIBOLIT_MAX_NUMBER);
     $l_RawReport['doorway'] = getRawJson($g_Doorway);
     $l_Result .= '<div class="note_warn">' . AI_STR_034 . '</div><div class="warn">';
     $l_Result .= printList($g_Doorway);
     $l_Result .= "</div>" . PHP_EOL;

   }

   stdOut("Building list of php warnings " . (count($g_WarningPHP[0]) + count($g_WarningPHP[1])));

   if (($defaults['report_mask'] & REPORT_MASK_SUSP) == REPORT_MASK_SUSP) {
      if ((count($g_WarningPHP[0]) + count($g_WarningPHP[1])) > 0) {
        $g_WarningPHP[0] = array_slice($g_WarningPHP[0], 0, AIBOLIT_MAX_NUMBER);
        $g_WarningPHP[1] = array_slice($g_WarningPHP[1], 0, AIBOLIT_MAX_NUMBER);
        $l_Result .= '<div class="note_warn">' . AI_STR_035 . '</div><div class="warn">';

        for ($i = 0; $i < count($g_WarningPHP); $i++) {
            if (count($g_WarningPHP[$i]) > 0) 
               $l_Result .= printList($g_WarningPHP[$i], $g_WarningPHPFragment[$i], true, $g_WarningPHPSig, 'table_warn' . $i);
        }                                                                                                                    
        $l_Result .= "</div>" . PHP_EOL;

      } 
   }

   stdOut("Building list of skipped dirs " . count($g_SkippedFolders));
   if (count($g_SkippedFolders) > 0) {
        $l_Result .= '<div class="note_warn">' . AI_STR_036 . '</div><div class="warn">';
        $l_Result .= nl2br(makeSafeFn(implode("\n", $g_SkippedFolders), true));   
        $l_Result .= "</div>" . PHP_EOL;
    }

    if (count($g_CMS) > 0) {
         $l_RawReport['cms'] = $g_CMS;
         $l_Result .= "<div class=\"note_warn\">" . AI_STR_037 . "<br/>";
         $l_Result .= nl2br(makeSafeFn(implode("\n", $g_CMS)));
         $l_Result .= "</div>";
    }
}

if (ICHECK) {
	$l_Result .= "<div style=\"margin-top: 20px\" class=\"title\">" . AI_STR_087 . "</div>";
	
    stdOut("Building list of added files " . count($changes['addedFiles']));
    if (count($changes['addedFiles']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_082 . ' (' . count($changes['addedFiles']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['addedFiles']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of modified files " . count($changes['modifiedFiles']));
    if (count($changes['modifiedFiles']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_083 . ' (' . count($changes['modifiedFiles']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['modifiedFiles']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of deleted files " . count($changes['deletedFiles']));
    if (count($changes['deletedFiles']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_084 . ' (' . count($changes['deletedFiles']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['deletedFiles']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of added dirs " . count($changes['addedDirs']));
    if (count($changes['addedDirs']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_085 . ' (' . count($changes['addedDirs']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['addedDirs']);
      $l_Result .= "</div>" . PHP_EOL;
    }

    stdOut("Building list of deleted dirs " . count($changes['deletedDirs']));
    if (count($changes['deletedDirs']) > 0) {
      $l_Result .= '<div class="note_int">' . AI_STR_086 . ' (' . count($changes['deletedDirs']) . ')</div><div class="intitem">';
      $l_Result .= printList($changes['deletedDirs']);
      $l_Result .= "</div>" . PHP_EOL;
    }
}

if (!isCli()) {
   $l_Result .= QCR_ExtractInfo($l_PhpInfoBody[1]);
}


if (function_exists('memory_get_peak_usage')) {
  $l_Template = str_replace("@@MEMORY@@", AI_STR_043 . bytes2Human(memory_get_peak_usage()), $l_Template);
}

$l_Template = str_replace('@@WARN_QUICK@@', ((SCAN_ALL_FILES || $g_SpecificExt) ? '' : AI_STR_045), $l_Template);

if ($l_ShowOffer) {
	$l_Template = str_replace('@@OFFER@@', $l_Offer, $l_Template);
} else {
	$l_Template = str_replace('@@OFFER@@', AI_STR_002, $l_Template);
}

$l_Template = str_replace('@@OFFER2@@', $l_Offer2, $l_Template);

$l_Template = str_replace('@@CAUTION@@', AI_STR_003, $l_Template);

$l_Template = str_replace('@@CREDITS@@', AI_STR_075, $l_Template);

$l_Template = str_replace('@@FOOTER@@', AI_STR_076, $l_Template);

$l_Template = str_replace('@@STAT@@', sprintf(AI_STR_012, $time_taken, date('d-m-Y в H:i:s', floor(START_TIME)) , date('d-m-Y в H:i:s')), $l_Template);

////////////////////////////////////////////////////////////////////////////
$l_Template = str_replace("@@MAIN_CONTENT@@", $l_Result, $l_Template);

if (!isCli())
{
    echo $l_Template;
    exit;
}

if (!defined('REPORT') OR REPORT === '')
{
	die2('Report not written.');
}
 
// write plain text result
if (PLAIN_FILE != '') {
	
    $l_PlainResult = preg_replace('|__AI_LINE1__|smi', '[', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_LINE2__|smi', '] ', $l_PlainResult);
    $l_PlainResult = preg_replace('|__AI_MARKER__|smi', ' %> ', $l_PlainResult);

   if ($l_FH = fopen(PLAIN_FILE, "w")) {
      fputs($l_FH, $l_PlainResult);
      fclose($l_FH);
   }
}

// write json result
if (defined('JSON_FILE')) {	
   if ($l_FH = fopen(JSON_FILE, "w")) {
      fputs($l_FH, json_encode($l_RawReport));
      fclose($l_FH);
   }
}

// write serialized result
if (defined('PHP_FILE')) {	
   if ($l_FH = fopen(PHP_FILE, "w")) {
      fputs($l_FH, serialize($l_RawReport));
      fclose($l_FH);
   }
}

$emails = getEmails(REPORT);

if (!$emails) {
	if ($l_FH = fopen($file, "w")) {
	   fputs($l_FH, $l_Template);
	   fclose($l_FH);
	   stdOut("\nReport written to '$file'.");
	} else {
		stdOut("\nCannot create '$file'.");
	}
}	else	{
		$headers = array(
			'MIME-Version: 1.0',
			'Content-type: text/html; charset=UTF-8',
			'From: ' . ($defaults['email_from'] ? $defaults['email_from'] : 'AI-Bolit@myhost')
		);

		for ($i = 0, $size = sizeof($emails); $i < $size; $i++)
		{
			mail($emails[$i], 'AI-Bolit Report ' . date("d/m/Y H:i", time()), $l_Result, implode("\r\n", $headers));
		}

		stdOut("\nReport sended to " . implode(', ', $emails));
}


$time_taken = microtime(true) - START_TIME;
$time_taken = number_format($time_taken, 5);


stdOut("Scanning complete! Time taken: " . seconds2Human($time_taken));

if (DEBUG_PERFORMANCE) {
   $keys = array_keys($g_RegExpStat);
   for ($i = 0; $i < count($keys); $i++) {
       $g_RegExpStat[$keys[$i]] = round($g_RegExpStat[$keys[$i]] * 1000000);
   }

   arsort($g_RegExpStat);

   foreach ($g_RegExpStat as $r => $v) {
      echo $v . "\t\t" . $r . "\n";
   }

   die();
}

stdOut("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
stdOut("Attention! DO NOT LEAVE either ai-bolit.php or AI-BOLIT-REPORT-<xxxx>-<yy>.html \nfile on server. COPY it locally then REMOVE from server. ");
stdOut("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

if (isset($options['quarantine'])) {
	Quarantine();
}

if (isset($options['cmd'])) {
	stdOut("Run \"{$options['cmd']}\" ");
	system($options['cmd']);
}

QCR_Debug();

# exit with code

$l_EC1 = count($g_CriticalPHP);
$l_EC2 = count($g_CriticalJS) + count($g_Phishing) + count($g_WarningPHP[0]) + count($g_WarningPHP[1]);
$code = 0;

if ($l_EC1 > 0) {
	$code = 2;
} else {
	if ($l_EC2 > 0) {
		$code = 1;
	}
}

$stat = array('php_malware' => count($g_CriticalPHP), 'js_malware' => count($g_CriticalJS), 'phishing' => count($g_Phishing));

if (function_exists('aibolit_onComplete')) { aibolit_onComplete($code, $stat); }

stdOut('Exit code ' . $code);
exit($code);

############################################# END ###############################################

function Quarantine()
{
	if (!file_exists(DOUBLECHECK_FILE)) {
		return;
	}
	
	$g_QuarantinePass = 'aibolit';
	
	$archive = "AI-QUARANTINE-" .rand(100000, 999999) . ".zip";
	$infoFile = substr($archive, 0, -3) . "txt";
	$report = REPORT_PATH . DIR_SEPARATOR . REPORT_FILE;
	

	foreach (file(DOUBLECHECK_FILE) as $file) {
		$file = trim($file);
		if (!is_file($file)) continue;
	
		$lStat = stat($file);
		
		// skip files over 300KB
		if ($lStat['size'] > 300*1024) continue;

		// http://www.askapache.com/security/chmod-stat.html
		$p = $lStat['mode'];
		$perm ='-';
		$perm.=(($p&0x0100)?'r':'-').(($p&0x0080)?'w':'-');
		$perm.=(($p&0x0040)?(($p&0x0800)?'s':'x'):(($p&0x0800)?'S':'-'));
		$perm.=(($p&0x0020)?'r':'-').(($p&0x0010)?'w':'-');
		$perm.=(($p&0x0008)?(($p&0x0400)?'s':'x'):(($p&0x0400)?'S':'-'));
		$perm.=(($p&0x0004)?'r':'-').(($p&0x0002)?'w':'-');
		$perm.=(($p&0x0001)?(($p&0x0200)?'t':'x'):(($p&0x0200)?'T':'-'));
		
		$owner = (function_exists('posix_getpwuid'))? @posix_getpwuid($lStat['uid']) : array('name' => $lStat['uid']);
		$group = (function_exists('posix_getgrgid'))? @posix_getgrgid($lStat['gid']) : array('name' => $lStat['uid']);

		$inf['permission'][] = $perm;
		$inf['owner'][] = $owner['name'];
		$inf['group'][] = $group['name'];
		$inf['size'][] = $lStat['size'] > 0 ? bytes2Human($lStat['size']) : '-';
		$inf['ctime'][] = $lStat['ctime'] > 0 ? date("d/m/Y H:i:s", $lStat['ctime']) : '-';
		$inf['mtime'][] = $lStat['mtime'] > 0 ? date("d/m/Y H:i:s", $lStat['mtime']) : '-';
		$files[] = strpos($file, './') === 0 ? substr($file, 2) : $file;
	}
	
	// get config files for cleaning
	$configFilesRegex = 'config(uration|\.in[ic])?\.php$|dbconn\.php$';
	$configFiles = preg_grep("~$configFilesRegex~", $files);

	// get columns width
	$width = array();
	foreach (array_keys($inf) as $k) {
		$width[$k] = strlen($k);
		for ($i = 0; $i < count($inf[$k]); ++$i) {
			$len = strlen($inf[$k][$i]);
			if ($len > $width[$k])
				$width[$k] = $len;
		}
	}

	// headings of columns
	$info = '';
	foreach (array_keys($inf) as $k) {
		$info .= str_pad($k, $width[$k], ' ', STR_PAD_LEFT). ' ';
	}
	$info .= "name\n";
	
	for ($i = 0; $i < count($files); ++$i) {
		foreach (array_keys($inf) as $k) {
			$info .= str_pad($inf[$k][$i], $width[$k], ' ', STR_PAD_LEFT). ' ';
		}
		$info .= $files[$i]."\n";
	}
	unset($inf, $width);

	exec("zip -v 2>&1", $output,$code);

	if ($code == 0) {
		$filter = '';
		if ($configFiles && exec("grep -V 2>&1", $output, $code) && $code == 0) {
			$filter = "|grep -v -E '$configFilesRegex'";
		}

		exec("cat AI-BOLIT-DOUBLECHECK.php $filter |zip -@ --password $g_QuarantinePass $archive", $output, $code);
		if ($code == 0) {
			file_put_contents($infoFile, $info);
			$m = array();
			if (!empty($filter)) {
				foreach ($configFiles as $file) {
					$tmp = file_get_contents($file);
					// remove  passwords
					$tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
					// new file name
					$file = preg_replace('~.*/~', '', $file) . '-' . rand(100000, 999999);
					file_put_contents($file, $tmp);
					$m[] = $file;
				}
			}

			exec("zip -j --password $g_QuarantinePass $archive $infoFile $report " . DOUBLECHECK_FILE . ' ' . implode(' ', $m));
			stdOut("\nCreate archive '" . realpath($archive) . "'");
			stdOut("This archive have password '$g_QuarantinePass'");
			foreach ($m as $file) unlink($file);
			unlink($infoFile);
			return;
		}
	}
	
	$zip = new ZipArchive;
	
	if ($zip->open($archive, ZIPARCHIVE::CREATE | ZIPARCHIVE::OVERWRITE) === false) {
		stdOut("Cannot create '$archive'.");
		return;
	}

	foreach ($files as $file) {
		if (in_array($file, $configFiles)) {
			$tmp = file_get_contents($file);
			// remove  passwords
			$tmp = preg_replace('~^.*?pass.*~im', '', $tmp);
			$zip->addFromString($file, $tmp);
		} else {
			$zip->addFile($file);
		}
	}
	$zip->addFile(DOUBLECHECK_FILE, DOUBLECHECK_FILE);
	$zip->addFile($report, REPORT_FILE);
	$zip->addFromString($infoFile, $info);
	$zip->close();

	stdOut("\nCreate archive '" . realpath($archive) . "'.");
	stdOut("This archive has no password!");
}



///////////////////////////////////////////////////////////////////////////
function QCR_IntegrityCheck($l_RootDir)
{
	global $g_Structure, $g_Counter, $g_Doorway, $g_FoundTotalFiles, $g_FoundTotalDirs, 
			$defaults, $g_SkippedFolders, $g_UrlIgnoreList, $g_DirIgnoreList, $g_UnsafeDirArray, 
                        $g_UnsafeFilesFound, $g_SymLinks, $g_HiddenFiles, $g_UnixExec, $g_IgnoredExt, $g_SuspiciousFiles, $l_SkipSample;
	global $g_IntegrityDB, $g_ICheck;
	static $l_Buffer = '';
	
	$l_DirCounter = 0;
	$l_DoorwayFilesCounter = 0;
	$l_SourceDirIndex = $g_Counter - 1;
	
	QCR_Debug('Check ' . $l_RootDir);

 	if ($l_DIRH = @opendir($l_RootDir))
	{
		while (($l_FileName = readdir($l_DIRH)) !== false)
		{
			if ($l_FileName == '.' || $l_FileName == '..') continue;

			$l_FileName = $l_RootDir . DIR_SEPARATOR . $l_FileName;

			$l_Type = filetype($l_FileName);
			$l_IsDir = ($l_Type == "dir");
            if ($l_Type == "link") 
            {
				$g_SymLinks[] = $l_FileName;
                continue;
            } else 
			if ($l_Type != "file" && (!$l_IsDir)) {
				$g_UnixExec[] = $l_FileName;
				continue;
			}	
						
			$l_Ext = substr($l_FileName, strrpos($l_FileName, '.') + 1);

			$l_NeedToScan = true;
			$l_Ext2 = substr(strstr(basename($l_FileName), '.'), 1);
			if (in_array(strtolower($l_Ext2), $g_IgnoredExt)) {
                           $l_NeedToScan = false;
            		}

      			// if folder in ignore list
      			$l_Skip = false;
      			for ($dr = 0; $dr < count($g_DirIgnoreList); $dr++) {
      				if (($g_DirIgnoreList[$dr] != '') &&
      				   preg_match('#' . $g_DirIgnoreList[$dr] . '#', $l_FileName, $l_Found)) {
      				   if (!in_array($g_DirIgnoreList[$dr], $l_SkipSample)) {
                                      $l_SkipSample[] = $g_DirIgnoreList[$dr];
                                   } else {
        		             $l_Skip = true;
                                     $l_NeedToScan = false;
                                   }
      				}
      			}
      					
			if (getRelativePath($l_FileName) == "./" . INTEGRITY_DB_FILE) $l_NeedToScan = false;

			if ($l_IsDir)
			{
				// skip on ignore
				if ($l_Skip) {
				   $g_SkippedFolders[] = $l_FileName;
				   continue;
				}
				
				$l_BaseName = basename($l_FileName);

				$l_DirCounter++;

				$g_Counter++;
				$g_FoundTotalDirs++;

				QCR_IntegrityCheck($l_FileName);

			} else
			{
				if ($l_NeedToScan)
				{
					$g_FoundTotalFiles++;
					$g_Counter++;
				}
			}
			
			if (!$l_NeedToScan) continue;

			if (IMAKE) {
				write_integrity_db_file($l_FileName);
				continue;
			}

			// ICHECK
			// skip if known and not modified.
			if (icheck($l_FileName)) continue;
			
			$l_Buffer .= getRelativePath($l_FileName);
			$l_Buffer .= $l_IsDir ? DIR_SEPARATOR . "\n" : "\n";

			if (strlen($l_Buffer) > 32000)
			{
				file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
				$l_Buffer = '';
			}

		}

		closedir($l_DIRH);
	}
	
	if (($l_RootDir == ROOT_PATH) && !empty($l_Buffer)) {
		file_put_contents(QUEUE_FILENAME, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . QUEUE_FILENAME);
		$l_Buffer = '';
	}

	if (($l_RootDir == ROOT_PATH)) {
		write_integrity_db_file();
	}

}


function getRelativePath($l_FileName) {
	return "./" . substr($l_FileName, strlen(ROOT_PATH) + 1) . (is_dir($l_FileName) ? DIR_SEPARATOR : '');
}
/**
 *
 * @return true if known and not modified
 */
function icheck($l_FileName) {
	global $g_IntegrityDB, $g_ICheck;
	static $l_Buffer = '';
	static $l_status = array( 'modified' => 'modified', 'added' => 'added' );
    
	$l_RelativePath = getRelativePath($l_FileName);
	$l_known = isset($g_IntegrityDB[$l_RelativePath]);

	if (is_dir($l_FileName)) {
		if ( $l_known ) {
			unset($g_IntegrityDB[$l_RelativePath]);
		} else {
			$g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
		}
		return $l_known;
	}

	if ($l_known == false) {
		$g_IntegrityDB[$l_RelativePath] =& $l_status['added'];
		return false;
	}

	$hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';
	
	if ($g_IntegrityDB[$l_RelativePath] != $hash) {
		$g_IntegrityDB[$l_RelativePath] =& $l_status['modified'];
		return false;
	}

	unset($g_IntegrityDB[$l_RelativePath]);
	return true;
}

function write_integrity_db_file($l_FileName = '') {
	static $l_Buffer = '';

	if (empty($l_FileName)) {
		empty($l_Buffer) or file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
		$l_Buffer = '';
		return;
	}

	$l_RelativePath = getRelativePath($l_FileName);
		
	$hash = is_file($l_FileName) ? hash_file('sha1', $l_FileName) : '';

	$l_Buffer .= "$l_RelativePath|$hash\n";
	
	if (strlen($l_Buffer) > 32000)
	{
		file_put_contents('compress.zlib://' . INTEGRITY_DB_FILE, $l_Buffer, FILE_APPEND) or die2("Cannot write to file " . INTEGRITY_DB_FILE);
		$l_Buffer = '';
	}
}

function load_integrity_db() {
	global $g_IntegrityDB;
	file_exists(INTEGRITY_DB_FILE) or die2('Not found ' . INTEGRITY_DB_FILE);

	$s_file = new SplFileObject('compress.zlib://'.INTEGRITY_DB_FILE);
	$s_file->setFlags(SplFileObject::READ_AHEAD | SplFileObject::SKIP_EMPTY | SplFileObject::DROP_NEW_LINE);

	foreach ($s_file as $line) {
		$i = strrpos($line, '|');
		if (!$i) continue;
		$g_IntegrityDB[substr($line, 0, $i)] = substr($line, $i+1);
	}

	$s_file = null;
}


function OptimizeSignatures()
{
	global $g_DBShe, $g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe;
	global $g_JSVirSig, $gX_JSVirSig;
	global $g_AdwareSig;
	global $g_PhishingSig;
	global $g_ExceptFlex, $g_SusDBPrio, $g_SusDB;

	(AI_EXPERT == 2) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe, $gXX_FlexDBShe));
	(AI_EXPERT == 1) && ($g_FlexDBShe = array_merge($g_FlexDBShe, $gX_FlexDBShe));
	$gX_FlexDBShe = $gXX_FlexDBShe = array();

	(AI_EXPERT == 2) && ($g_JSVirSig = array_merge($g_JSVirSig, $gX_JSVirSig));
	$gX_JSVirSig = array();

	$count = count($g_FlexDBShe);

	for ($i = 0; $i < $count; $i++) {
		if ($g_FlexDBShe[$i] == '[a-zA-Z0-9_]+?\(\s*[a-zA-Z0-9_]+?=\s*\)') $g_FlexDBShe[$i] = '\((?<=[a-zA-Z0-9_].)\s*[a-zA-Z0-9_]++=\s*\)';
		if ($g_FlexDBShe[$i] == '([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e') $g_FlexDBShe[$i] = '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e';
		if ($g_FlexDBShe[$i] == '$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.$[a-zA-Z0-9_]\{\d+\}\s*\.') $g_FlexDBShe[$i] = '\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.\$[a-zA-Z0-9_]\{\d+\}\s*\.';

		$g_FlexDBShe[$i] = str_replace('http://.+?/.+?\.php\?a', 'http://[^?\s]++(?<=\.php)\?a', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = preg_replace('~\[a-zA-Z0-9_\]\+\K\?~', '+', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = preg_replace('~^\\\\[d]\+&@~', '&@(?<=\d..)', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = str_replace('\s*[\'"]{0,1}.+?[\'"]{0,1}\s*', '.+?', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = str_replace('[\'"]{0,1}.+?[\'"]{0,1}', '.+?', $g_FlexDBShe[$i]);

		$g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
		$g_FlexDBShe[$i] = preg_replace('~^\[\'"\]\{0,1\}\.?|^@\*|^\\\\s\*~', '', $g_FlexDBShe[$i]);
	}

	optSig($g_FlexDBShe);

	optSig($g_JSVirSig);
	
	
        
        //optSig($g_SusDBPrio);
        //optSig($g_ExceptFlex);

        // convert exception rules
        $cnt = count($g_ExceptFlex);
        for ($i = 0; $i < $cnt; $i++) {                		
            $g_ExceptFlex[$i] = trim(UnwrapObfu($g_ExceptFlex[$i]));
            if (!strlen($g_ExceptFlex[$i])) unset($g_ExceptFlex[$i]);
        }

        $g_ExceptFlex = array_values($g_ExceptFlex);
}

function optSig(&$sigs)
{
	$sigs = array_unique($sigs);

	// Add SigId
	foreach ($sigs as &$s) {
		$s .= '(?<X' . myCheckSum($s) . '>)';
	}
	unset($s);
	
	$fix = array(
		'([^\?\s])\({0,1}\.[\+\*]\){0,1}\2[a-z]*e' => '(?J)\.[+*](?<=(?<d>[^\?\s])\(..|(?<d>[^\?\s])..)\)?\g{d}[a-z]*e',
		'http://.+?/.+?\.php\?a' => 'http://[^?\s]++(?<=\.php)\?a',
		'\s*[\'"]{0,1}.+?[\'"]{0,1}\s*' => '.+?',
		'[\'"]{0,1}.+?[\'"]{0,1}' => '.+?'
	);

	$sigs = str_replace(array_keys($fix), array_values($fix), $sigs);
	
	$fix = array(
		'~^\\\\[d]\+&@~' => '&@(?<=\d..)',
		'~^((\[\'"\]|\\\\s|@)(\{0,1\}\.?|[?*]))+~' => ''
	);

	$sigs = preg_replace(array_keys($fix), array_values($fix), $sigs);

	optSigCheck($sigs);

	$tmp = array();
	foreach ($sigs as $i => $s) {
		if (!preg_match('#^(?>(?!\.[*+]|\\\\\d)(?:\\\\.|\[.+?\]|.))+$#', $s)) {
			unset($sigs[$i]);
			$tmp[] = $s;
		}
	}
	
	usort($sigs, 'strcasecmp');
	$txt = implode("\n", $sigs);

	for ($i = 24; $i >= 1; ($i > 4 ) ? $i -= 4 : --$i) {
	    $txt = preg_replace_callback('#^((?>(?:\\\\.|\\[.+?\\]|[^(\n]|\((?:\\\\.|[^)(\n])++\))(?:[*?+]\+?|\{\d+(?:,\d*)?\}[+?]?|)){' . $i . ',})[^\n]*+(?:\\n\\1(?![{?*+]).+)+#im', 'optMergePrefixes', $txt);
	}

	$sigs = array_merge(explode("\n", $txt), $tmp);
	
	optSigCheck($sigs);
}

function optMergePrefixes($m)
{
	$limit = 8000;
	
	$prefix = $m[1];
	$prefix_len = strlen($prefix);

	$len = $prefix_len;
	$r = array();

	$suffixes = array();
	foreach (explode("\n", $m[0]) as $line) {
	
	  if (strlen($line)>$limit) {
	    $r[] = $line;
	    continue;
	  }
	
	  $s = substr($line, $prefix_len);
	  $len += strlen($s);
	  if ($len > $limit) {
	    if (count($suffixes) == 1) {
	      $r[] = $prefix . $suffixes[0];
	    } else {
	      $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
	    }
	    $suffixes = array();
	    $len = $prefix_len + strlen($s);
	  }
	  $suffixes[] = $s;
	}

	if (!empty($suffixes)) {
	  if (count($suffixes) == 1) {
	    $r[] = $prefix . $suffixes[0];
	  } else {
	    $r[] = $prefix . '(?:' . implode('|', $suffixes) . ')';
	  }
	}
	
	return implode("\n", $r);
}

function optMergePrefixes_Old($m)
{
	$prefix = $m[1];
	$prefix_len = strlen($prefix);

	$suffixes = array();
	foreach (explode("\n", $m[0]) as $line) {
	  $suffixes[] = substr($line, $prefix_len);
	}

	return $prefix . '(?:' . implode('|', $suffixes) . ')';
}

/*
 * Checking errors in pattern
 */
function optSigCheck(&$sigs)
{
	$result = true;

	foreach ($sigs as $k => $sig) {
                if (trim($sig) == "") {
                   if (DEBUG_MODE) {
                      echo("************>>>>> EMPTY\n     pattern: " . $sig . "\n");
                   }
	           unset($sigs[$k]);
		   $result = false;
                }

		if (@preg_match('#' . $sig . '#smiS', '') === false) {
			$error = error_get_last();
                        if (DEBUG_MODE) {
			   echo("************>>>>> " . $error['message'] . "\n     pattern: " . $sig . "\n");
                        }
			unset($sigs[$k]);
			$result = false;
		}
	}
	
	return $result;
}

function _hash_($text)
{
	static $r;
	
	if (empty($r)) {
		for ($i = 0; $i < 256; $i++) {
			if ($i < 33 OR $i > 127 ) $r[chr($i)] = '';
		}
	}

	return sha1(strtr($text, $r));
}

function check_whitelist($list, &$snum) 
{
	if (empty($list)) return array();
	
	$file = dirname(__FILE__) . '/AIBOLIT-WHITELIST.db';

	$snum = max(0, @filesize($file) - 1024) / 20;
	stdOut("\nLoaded " . ceil($snum) . " known files\n");
	
	sort($list);

	$hash = reset($list);
	
	$fp = @fopen($file, 'rb');
	
	if (false === $fp) return array();
	
	$header = unpack('V256', fread($fp, 1024));
	
	$result = array();
	
	foreach ($header as $chunk_id => $chunk_size) {
		if ($chunk_size > 0) {
			$str = fread($fp, $chunk_size);
			
			do {
				$raw = pack("H*", $hash);
				$id = ord($raw[0]) + 1;
				
				if ($chunk_id == $id AND binarySearch($str, $raw)) {
					$result[] = $hash;
				}
				
			} while ($chunk_id >= $id AND $hash = next($list));
			
			if ($hash === false) break;
		}
	}
	
	fclose($fp);

	return $result;
}


function binarySearch($str, $item)
{
	$item_size = strlen($item);	
	if ( $item_size == 0 ) return false;
	
	$first = 0;

	$last = floor(strlen($str) / $item_size);
	
	while ($first < $last) {
		$mid = $first + (($last - $first) >> 1);
		$b = substr($str, $mid * $item_size, $item_size);
		if (strcmp($item, $b) <= 0)
			$last = $mid;
		else
			$first = $mid + 1;
	}

	$b = substr($str, $last * $item_size, $item_size);
	if ($b == $item) {
		return true;
	} else {
		return false;
	}
}

function getSigId($l_Found)
{
	foreach ($l_Found as $key => &$v) {
		if (is_string($key) AND $v[1] != -1 AND strlen($key) == 9) {
			return substr($key, 1);
		}
	}
	
	return null;
}

function die2($str) {
  if (function_exists('aibolit_onFatalError')) { aibolit_onFatalError($str); }
  die($str);
}

function checkFalsePositives($l_Filename, $l_Unwrapped, $l_DeobfType) {
  global $g_DeMapper;

  if ($l_DeobfType != '') {
     if (DEBUG_MODE) {
       stdOut("\n-----------------------------------------------------------------------------\n");
       stdOut("[DEBUG]" . $l_Filename . "\n");
       var_dump(getFragment($l_Unwrapped, $l_Pos));
       stdOut("\n...... $l_DeobfType ...........\n");
       var_dump($l_Unwrapped);
       stdOut("\n");
     }

     switch ($l_DeobfType) {
        case '_GLOBALS_': 
           foreach ($g_DeMapper as $fkey => $fvalue) {
              if (DEBUG_MODE) {
                 stdOut("[$fkey] => [$fvalue]\n");
              }

              if ((strpos($l_Filename, $fkey) !== false) &&
                  (strpos($l_Unwrapped, $fvalue) !== false)) {
                 if (DEBUG_MODE) {
                    stdOut("\n[DEBUG] *** SKIP: False Positive\n");
                 } 

                 return true;
              }
           }
        break;
     }


     return false;
  }
}

function deobfuscate_bitrix($str)
{
	global $varname,$funclist,$strlist;
	$res = $str;
	$funclist = array();
	$strlist = array();
	$res = preg_replace("|'\s*\.\s*'|smi", '', $res);
	$res = preg_replace_callback(
		'|(round\((.+?)\))|smi',
		function ($matches) {
		   return round($matches[2]);
		},
		$res
	);
	$res = preg_replace_callback(
			'|base64_decode\(\'(.*?)\'\)|smi',
			function ($matches) {
				return "'" . base64_decode($matches[1]) . "'";
			},
			$res
	);

	$res = preg_replace_callback(
			'|\'(.*?)\'|sm',
			function ($matches) {
				$temp = base64_decode($matches[1]);
				if (base64_encode($temp) === $matches[1] && preg_match('#^[ -~]*$#', $temp)) { 
				   return "'" . $temp . "'";
				} else {
				   return "'" . $matches[1] . "'";
				}
			},
			$res
	);	

	if (preg_match_all('|\$GLOBALS\[\'(.+?)\'\]\s*=\s*Array\((.+?)\);|smi', $res, $founds, PREG_SET_ORDER)) {
   	foreach($founds as $found)
   	{
   		$varname = $found[1];
   		$funclist[$varname] = explode(',', $found[2]);
   		$funclist[$varname] = array_map(function($value) { return trim($value, "'"); }, $funclist[$varname]);

   		$res = preg_replace_callback(
   				'|\$GLOBALS\[\'' . $varname . '\'\]\[(\d+)\]|smi',
   				function ($matches) {
   				   global $varname, $funclist;
   				   return $funclist[$varname][$matches[1]];
   				},
   				$res
   		);
   		
     	        $res = preg_replace('~' . quotemeta(str_replace('~', '.', $found[0])) . '~smi', '', $res);
   	}
        }
		

	if (preg_match_all('|function _+(\d+)\(\$i\){\$a=Array\((.+?)\);[^}]+}|smi', $res, $founds, PREG_SET_ORDER)) {
	foreach($founds as $found)
	{
		$strlist = explode(',', $found[2]);

		$res = preg_replace_callback(
				'|_' . $found[1] . '\((\d+)\)|smi',
				function ($matches) {
				   global $strlist;
				   return $strlist[$matches[1]];
				},
				$res
		);

  	        $res = preg_replace('~' . quotemeta(str_replace('~', '\\~', $found[0])) . '~smi', '', $res);
	}
        }

  	$res = preg_replace('~<\?(php)?\s*\?>~smi', '', $res);

	preg_match_all('~function (_+(.+?))\(\$[_0-9]+\)\{\s*static\s*\$([_0-9]+)\s*=\s*(true|false);.*?\$\3=array\((.*?)\);\s*return\s*base64_decode\(\$\3~smi', $res, $founds,PREG_SET_ORDER);
	foreach($founds as $found)
	{
		$strlist = explode("',",$found[5]);
		$res = preg_replace_callback(
				'|' . $found[1] . '\((\d+)\)|sm',
				function ($matches) {
				   global $strlist;
				   return $strlist[$matches[1]]."'";
				},
				$res
		);
				
	}

	$res = preg_replace('|;|sm', ";\n", $res);

	return $res;
}

function my_eval($matches)
{
    $string = $matches[0];
    $string = substr($string, 5, strlen($string) - 7);
    return decode($string);
}

function decode($string, $level = 0)
{
    if (trim($string) == '') return '';
    if ($level > 100) return '';

    if (($string[0] == '\'') || ($string[0] == '"')) {
        return substr($string, 1, strlen($string) - 2); //
	} elseif ($string[0] == '$') {
        return $string; //
    } else {
        $pos      = strpos($string, '(');
        $function = substr($string, 0, $pos);
		
        $arg      = decode(substr($string, $pos + 1), $level + 1);
    	if ($function == 'base64_decode') return @base64_decode($arg);
    	else if ($function == 'gzinflate') return @gzinflate($arg);
		else if ($function == 'gzuncompress') return @gzuncompress($arg);
    	else if ($function == 'strrev')  return @strrev($arg);
    	else if ($function == 'str_rot13')  return @str_rot13($arg);
    	else return $arg;
    }    
}
    
function deobfuscate_eval($str)
{
    $res = preg_replace_callback('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress).*?\);~ms', "my_eval", $str);
    return $res;
}

function getEvalCode($string)
{
    preg_match("/eval\((.*?)\);/", $string, $matches);
    return (empty($matches)) ? '' : end($matches);
}
function getTextInsideQuotes($string)
{
    preg_match('/("(.*?)")/', $string, $matches);
    return (empty($matches)) ? '' : end($matches);
}

function deobfuscate_lockit($str)
{    
    $obfPHP        = $str;
    $phpcode       = base64_decode(getTextInsideQuotes(getEvalCode($obfPHP)));
    $hexvalues     = getHexValues($phpcode);
    $tmp_point     = getHexValues($obfPHP);
    $pointer1      = hexdec($tmp_point[0]);
    $pointer2      = hexdec($hexvalues[0]);
    $pointer3      = hexdec($hexvalues[1]);
    $needles       = getNeedles($phpcode);
    $needle        = $needles[count($needles) - 2];
    $before_needle = end($needles);
    
    
    $phpcode = base64_decode(strtr(substr($obfPHP, $pointer2 + $pointer3, $pointer1), $needle, $before_needle));
    return "<?php {$phpcode} ?>";
}


    function getNeedles($string)
    {
        preg_match_all("/'(.*?)'/", $string, $matches);
        
        return (empty($matches)) ? array() : $matches[1];
    }
    function getHexValues($string)
    {
        preg_match_all('/0x[a-fA-F0-9]{1,8}/', $string, $matches);
        return (empty($matches)) ? array() : $matches[0];
    }

function deobfuscate_als($str)
{
	preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi',$str,$layer1);

	preg_match('~\$[O0]+=(\$[O0]+\()+\$[O0]+,[0-9a-fx]+\),\'([^\']+)\',\'([^\']+)\'\)\);eval\(~msi',base64_decode($layer1[1]),$layer2);
    $res = explode("?>", $str);
	if (strlen($res[1])>0)
	{
		$res = substr($res[1], 380);
		$res = base64_decode(strtr($res, $layer2[2], $layer2[3]));
	}
    return "<?php {$res} ?>";
}

function deobfuscate_byterun($str)
{
	preg_match('~\$_F=__FILE__;\$_X=\'([^\']+)\';eval\(~ms',$str,$matches);
	$res = base64_decode($matches[1]);
	$res = strtr($res,'123456aouie','aouie123456');
    return "<?php {$res} ?>";
}

function deobfuscate_urldecode($str)
{
	preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi',$str,$matches);
	$alph = urldecode($matches[2]);
	$funcs=$matches[3];
	for($i = 0; $i < strlen($alph); $i++)
	{
		$funcs = str_replace($matches[1].'{'.$i.'}.',$alph[$i],$funcs);
		$funcs = str_replace($matches[1].'{'.$i.'}',$alph[$i],$funcs);
	}

	$str = str_replace($matches[3], $funcs, $str);
	$funcs = explode(';', $funcs);
	foreach($funcs as $func)
	{
		$func_arr = explode("=", $func);
		if (count($func_arr) == 2)
		{
			$func_arr[0] = str_replace('$', '', $func_arr[0]);
			$str = str_replace('${"GLOBALS"}["' . $func_arr[0] . '"]', $func_arr[1], $str);
		}			
	}

	return $str;
}


function formatPHP($string)
{
    $string = str_replace('<?php', '', $string);
    $string = str_replace('?>', '', $string);
    $string = str_replace(PHP_EOL, "", $string);
    $string = str_replace(";", ";\n", $string);
    return $string;
}

function deobfuscate_fopo($str)
{
    $phpcode = formatPHP($str);
    $phpcode = base64_decode(getTextInsideQuotes(getEvalCode($phpcode)));
    @$phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(end(explode(':', $phpcode))))));
    $old = '';
    while (($old != $phpcode) && (strlen(strstr($phpcode, '@eval($')) > 0)) {
        $old = $phpcode;
        $funcs = explode(';', $phpcode);
		if (count($funcs) == 5) $phpcode = gzinflate(base64_decode(str_rot13(getTextInsideQuotes(getEvalCode($phpcode)))));
		else if (count($funcs) == 4) $phpcode = gzinflate(base64_decode(getTextInsideQuotes(getEvalCode($phpcode))));
    }
    
    return substr($phpcode, 2);
}

function getObfuscateType($str)
{
if (preg_match('~eval\((base64_decode|gzinflate|strrev|str_rot13|gzuncompress)~ms', $str))
        return "eval";
    if (preg_match('~\$GLOBALS\[\'_+\d+\'\]=\s*array\(base64_decode\(~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~function _+\d+\(\$i\){\$a=Array~msi', $str))
        return "_GLOBALS_";
    if (preg_match('~__FILE__;\$[O0]+=[0-9a-fx]+;eval\(\$[O0]+\(\'([^\']+)\'\)\);return;~msi', $str))
        return "ALS-Fullsite";
    if (preg_match('~\$[O0]*=urldecode\(\'%66%67%36%73%62%65%68%70%72%61%34%63%6f%5f%74%6e%64\'\);\s*\$GLOBALS\[\'[O0]*\'\]=\$[O0]*~msi', $str))
        return "LockIt!";
    if (preg_match('~\$\w+="(\\\x?[0-9a-f]+){13}";@eval\(\$\w+\(~msi', $str))
        return "FOPO";
	if (preg_match('~\$_F=__FILE__;\$_X=\'([^\']+\');eval\(~ms', $str))
        return "ByteRun";
    if (preg_match('~(\$[O0_]+)=urldecode\("([%0-9a-f]+)"\);((\$[O0_]+=(\1\{\d+\}\.?)+;)+)~msi', $str))
        return "urldecode_globals";
	
}

function deobfuscate($str)
{
    switch (getObfuscateType($str)) {
        case '_GLOBALS_':
            $str = deobfuscate_bitrix($str);
            break;
        case 'eval':
            $str = deobfuscate_eval($str);
            break;
        case 'ALS-Fullsite':
            $str = deobfuscate_als($str);
            break;
        case 'LockIt!':
            $str = deobfuscate_lockit($str);
            break;
        case 'FOPO':
            $str = deobfuscate_fopo($str);
            break;
	case 'ByteRun':
            $str = deobfuscate_byterun($str);
            break;
	case 'urldecode_globals' :
            $str = deobfuscate_urldecode($str);
	    break;
    }
    
    return $str;
}
