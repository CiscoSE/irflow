var iconPanels = [];
var curProgress = 1;

function shouldHideSidebar() {
    if ($(window).width() < 992) {
        $('#styleguideSidebar').addClass('sidebar--hidden');
    }
}
function startProgress() {
    setTimeout(function () {
        curProgress += Math.floor(Math.random() * 25);
        if (curProgress >= 100) {
            curProgress = 100;
        }
        $('main #progressbar').attr('data-percentage', curProgress);
        $('main #progressbar').attr('data-balloon', curProgress + '%');
        $('main #progressbar .progressbar__label').html(curProgress + '%');

        if (curProgress == 100) {
            $('main #progressbar .progressbar__label').html('Upload Complete');
            $('main #progressbar').attr('data-balloon', 'Upload Complete');
        } else {
            startProgress();
        }
    }, 1000);
}
function jumpTo(ref) {
    document.location.href = "section-"+ref+".html#"+ref;
}
function doNav(url) {
    shouldHideSidebar();
    document.location.href = url;
}
function searchIcons(icon) {
    var ret = [];
    for (var ii=0;ii<iconPanels.length;ii++) {
        if (iconPanels[ii].innerText.indexOf(icon) !== -1) {
            ret.push(iconPanels[ii]);
        }
    }
    return ret;
}
function clearSearch() {
    setIcons(iconPanels);
}
function setActiveSlide(slide, animation) {
    $(slide).siblings().removeClass('active');
    $(slide).parent().parent().find('.carousel__slide').removeClass('active slideInLeftSmall slideInRightSmall fadeIn');
    $(slide).addClass('active');
    $(slide).parent().parent().find('#'+slide.id+'-content').addClass('active '+animation);
}

function setIcons (icons) {
    $('#icon-container').empty();
    $('#icon-container').append(icons);
    $('#icon-count').text(icons.length);
    $('#icon-total-count').text(iconPanels.length);
}
function debounce (func, wait) {
    var timeout;
    var context = this, args = arguments;
    clearTimeout(timeout);
    timeout = setTimeout(function () {
        func.apply(context, args);
    }, wait || 0);
}

$(document).ready(function() {

    // Build list of icons
    iconPanels = $('#icon-container .icon-panel');

    // Wire the icon search
    $('#icon-search-input').on('input', function() {
        var searchStr = $('#icon-search-input').val();
        if (searchStr !== '') {
            setIcons(searchIcons(searchStr));
        }
        else {
            clearSearch();
        }
    });

    // Wire the header sidebar toggle button
    $('#styleguideHeader .toggle-menu').click(function() {
        $('#styleguideSidebar').toggleClass('sidebar--hidden');
    });

    // Wire the sidebar drawer open/close toggles
    $('#styleguideSidebar .sidebar__drawer > a').click(function() {
        $(this).parent().toggleClass('sidebar__drawer--opened');
    });

    // Wire the sidebar selected item
    $('#styleguideSidebar .sidebar__item > a').click(function() {
        $('#styleguideSidebar .sidebar__item').removeClass('sidebar__item--selected');
        $(this).parent().addClass('sidebar__item--selected');
    });

    // Wire the sidebar examples
    $('main .sidebar__drawer > a').click(function() {
        $(this).parent().toggleClass('sidebar__drawer--opened');
    });
    $('main .sidebar__item > a').click(function() {
        $(this).parent().siblings().removeClass('sidebar__item--selected');
        $(this).parent().addClass('sidebar__item--selected');
    });

    // Wire the button group examples
    $('main .btn-group .btn').click(function() {
        $(this).siblings().removeClass('selected');
        $(this).addClass('selected');
    });

    // Wire the markup toggles
    $('main .markup').removeClass('active');
    $('main .markup-toggle').click(function() {
        $(this).parent().next().toggleClass('hide');
        $(this).next().toggleClass('hide').removeClass('text-blue').text('Copy'); // Toggle the clipboard copy. Should only display when code is viewable
        $(this).parent().toggleClass('active');

        if ($(this).hasClass('active')) {
            $(this).find('.markup-label').text('Hide Source ');
        }
        else if (!$(this).hasClass('active')) {
            $(this).find('.markup-label').text('View Source ');
        }
    });

    // Wire the markup clipboard
    $('main .clipboard-toggle').click(function() {
        clipboard.copy($(this).parent().parent().find('code.code-raw').text());
        $(this).addClass('text-blue').text('Copied!');
    });

    // Wire the tabs
    $('main li.tab').click(function() {
        $(this).siblings().removeClass('active');
        $(this).parent().parent().find('.tab-pane').removeClass('active');
        $(this).addClass('active');
        $(this).parent().parent().find('#'+this.id + '-content').addClass('active');
    });

    // Wire closeable alerts
    $('main .alert .alert__close').click(function() {
        $(this).parent().addClass('hide');
    });

    // Wire the gauge example
    $('main #input-gauge-example').bind('keyup mouseup', function() {
        var val = $('#input-gauge-example').val() * 1;
        if (val >= 0 && val <= 100) {
            $('#gauge-example').attr('data-percentage', val);
            $('#gauge-example-value').text(val);
        }
    });

    // Wire the Card pattern examples
    $('main a.card').click(function() {
        $(this).toggleClass('selected');
    });

    // Wire the Grid page example
    $('main #grid-group').click(function() {
        $(this).parent().find('#grid-group').removeClass('selected');
        var cls = 'grid--' + $(this).text();
        $('main .grid').removeClass('grid--3up');
        $('main .grid').removeClass('grid--4up');
        $('main .grid').removeClass('grid--5up');
        $('main .grid').addClass(cls);
        $(this).addClass('selected');
    });

    $('main #grid-gutters').change(function() {
        $('main #grid').css('gridGap', $(this).val()+'px');
    });

    $('main #grid-selectable').change(function() {
        $('main #grid').toggleClass('grid--selectable');
        $('main .grid .card').removeClass('selected');
    });

    $('main #grid.grid--selectable .card').click(function() {
        if ($(this).parent().hasClass('grid--selectable')) {
            $(this).toggleClass('selected');
        }
    });

    // Wire the carousel examples
    $('main .carousel__controls a.dot').click(function() {
        setActiveSlide(this, 'fadeIn');
    });
    $('main .carousel__controls a.back').click(function() {
        var last = $(this).parent().find('a.dot').last();
        var cur = $(this).parent().find('a.dot.active');
        var active = cur.prev();
        if (active[0].id === "") {
            active = last;
        }
        setActiveSlide(active[0], 'slideInLeftSmall');
    });
    $('main .carousel__controls a.next').click(function() {
        var first = $(this).parent().find('a.dot').first();
        var cur = $(this).parent().find('a.dot.active');
        var active = cur.next();
        if (active[0].id === "") {
            active = first;
        }
        setActiveSlide(active[0], 'slideInRightSmall');
    });

    // Check for anchor link in the URL
    var url = window.location.href;
    if (url.lastIndexOf('#') != -1) {
        var anchor = url.substring(url.lastIndexOf('#') + 1);
        $('#rootDrawer').addClass('sidebar__drawer--opened');
        $('#section-' + anchor).addClass('sidebar__item--selected').ScrollTo({ duration: 50 });
    }
    else if (url.indexOf('index.html') != -1) {
        $('#section-gettingStarted').addClass('sidebar__item--selected');
    }

    // Wire the progressbar example
    startProgress();

    // Wire the dropdown / select examples
    $('main .dropdown .btn').click(function(e) {
        e.stopPropagation();
        $(this).parent().toggleClass('active');
    });
    $('main .dropdown .select input').click(function(e) {
        e.stopPropagation();
        $(this).parent().parent().toggleClass('active');
    });
    $('main .dropdown .select ~.dropdown__menu a').click(function(e) {
        e.stopPropagation();

        // Check multi-select
        var cb = $(this).find('label.checkbox input');
        if (cb.length) {
            cb.prop('checked', !cb.prop('checked'));
            if (cb[0].id === 'global-animation') {
                $('body').toggleClass('cui--animated');
            }
            else if (cb[0].id === 'global-headermargins') {
                $('body').toggleClass('cui--headermargins');
            }
            else if (cb[0].id === 'global-spacing') {
                $('body').toggleClass('cui--compressed');
            }
            else if (cb[0].id === 'global-wide') {
                $('body').toggleClass('cui--wide');
            }
        }
        else { // Single select
            e.stopPropagation();
            var origVal = $(this).parent().parent().find('input').val();
            var newVal = $(this).text();

            $(this).parent().find('a').removeClass('selected');
            $(this).addClass('selected');
            $(this).parent().parent().find('input').val($(this).text());
            $(this).parent().parent().removeClass('active');

            var obj = $(this).parent().parent().find('input');
            if (obj[0].id === 'select-change-version') {
                if (origVal !== newVal) {
                    $("#uikit-css").attr('href', $(this).attr('data-value'));
                }
            }
        }
    });
    // Close dropdowns on clicks outside the dropdowns
    $(document).click(function() {
        $('main .dropdown').removeClass('active');
    });

    // Wire the modal examples
    $('main #modal-feedback-open').click(function() {
        $('.modal-backdrop').removeClass('hide');
        $('#modal-feedback').removeClass('hide');
    });
    $('main #modal-feedback-close').click(function() {
        $('.modal-backdrop').addClass('hide');
        $('#modal-feedback').addClass('hide');
    });
    $('main #modal-login-open').click(function() {
        $('.modal-backdrop').removeClass('hide');
        $('#modal-login').removeClass('hide');
    });
    $('main #modal-small-open').click(function() {
        $('.modal-backdrop').removeClass('hide');
        $('#modal-small').removeClass('hide');
    });
    $('main #modal-small-close').click(function() {
        $('.modal-backdrop').addClass('hide');
        $('#modal-small').addClass('hide');
    });
    $('main #modal-large-open').click(function() {
        $('.modal-backdrop').removeClass('hide');
        $('#modal-large').removeClass('hide');
    });
    $('main #modal-large-close').click(function() {
        $('.modal-backdrop').addClass('hide');
        $('#modal-large').addClass('hide');
    });
    $('.modal__close').click(function() {
        $('.modal-backdrop').addClass('hide');
        $('.modal').addClass('hide');
    });

    // Wire the masonry layout dropdowns
    $('main #masonry-columns-dropdown').change(function() {
        $('main #masonry-columns-example').removeClass();
        $('main #masonry-columns-example').addClass('masonry masonry--cols-' + this.value);
    });
    $('main #masonry-gaps-dropdown').change(function() {
        $('main #masonry-gaps-example').removeClass();
        $('main #masonry-gaps-example').addClass('masonry masonry--gap-' + this.value);
    });

    // Wire the selectable tables
    $('main .table.table--selectable tbody > tr').click(function() {
        $(this).toggleClass('active');
    });

    // Wire the global modifiers
    $('main #global-animation').change(function() {
        $('body').toggleClass('cui--animated');
    });
    $('main #global-headermargins').change(function() {
        $('body').toggleClass('cui--headermargins');
    });
    $('main #global-spacing').change(function() {
        $('body').toggleClass('cui--compressed');
    });

    // Listen of window changes and close the sidebar if necessary
    $(window).resize(function() {
        shouldHideSidebar();
    });

    setIcons(iconPanels);
    shouldHideSidebar();
});
