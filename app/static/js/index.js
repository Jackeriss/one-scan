$(function () {
  function scan() {
    let scheme = $('.scheme').val()
    let domain = $('.domain').val().split('/')[0]
    let domainReg = /^((?:([a-z0-9]\.|[a-z0-9][a-z0-9\-]{0,61}[a-z0-9])\.)+)([a-z0-9]{2,63}|(?:[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]))\.?$/
    if (domainReg.test(domain)){
      window.location.href = `/?scheme=${scheme}&domain=${domain}`
    } else {
      alert("This domain name is illegal.")
    }
  }
  function getQueryVariable(variable) {
    let query = window.location.search.substring(1);
    let vars = query.split("&");
    for (let i=0;i<vars.length;i++) {
      let pair = vars[i].split("=");
      if (pair[0] == variable){return pair[1];}
    }
    return(false);
  }
  function genResultHtml(data) {
    let result = ''
    for (let i in data) {
      result += '<div class="scannerResult'
      if (i % 2 == 0) {
        result += ' backgroudColor'
      }
      result += `"><div class="resultTitle">${data[i].name}</div>`
      if (Object.prototype.toString.call(data[i].result) === '[object Boolean]') {
        if (data[i].result === true) {
          result += '<div class="resultText pass iconfont">&#xe82b;</div>'
        } else {
          result += '<div class="resultText notPass iconfont">&#xe82a;</div>'
        }
      } else {
        result += '<div class="resultContent">'
        for (let j in data[i].result) {
          if (data[i].result[j].url) {
            result += `<a href="${data[i].result[j].url}" target="_blank">`
          }
          result += '<div class="resultText">'
          if (data[i].result[j].image) {
            result += `<img src="https://jackeriss-1252826939.file.myqcloud.com/one-scan/icons/${data[i].result[j].image}"/>`
          }
          result += `${data[i].result[j].name}</div>`
          if (data[i].result[j].url) {
            result += '</a>'
          }
        }
        result += '</div>'
      }
      result += '</div>'
    }
    return result
  }
  function showResult() {
    $('.result').removeClass('dn')
    $('.loading').fadeOut(800, function () {
      $('.loading').addClass('dn')
    })
  }
  function resultPage(scheme, domain) {
    $('.scheme').val(scheme)
    $('.domain').val(domain)
    $('.indexLogo').addClass('resultLogo')
    $('.indexSearchBlock').addClass('resultSearchBlock')
    $('.resultLogo').removeClass('indexLogo')
    $('.resultSearchBlock').removeClass('indexSearchBlock')
    $('.loading').fadeIn(800, function () {
      $('.loading').removeClass('dn')
    })
    let url = scheme + domain
    $.ajax({
      type: 'get',
      url: '/v1/scan',
      data: {
        url: url
      },
      dataType: 'json',
      success: function (data) {
        console.log(data);
        let jump = ''
        let result = ''
        if (data.code === 0) {
          let report = data.body.scan_report
          for (let i in report) {
            jump +=  `<a href="#scanner${i}"><div class="scannerJumpBlock"><span class="iconfont">&#xe767;</span><span class="scannerJump"> ${report[i].name}</span></div></a>`
            result += `<a href="#scanner${i}"><div class="scannerNameBlock" id="scanner${i}"><span class="iconfont">&#xe767;</span><span class="scannerName"> ${report[i].name}</span></div></a>`
            if (Object.prototype.toString.call(report[i].result) === '[object Object]') {
              for (let j in report[i].result) {
                result += `<div class="sub">${j}</div>`
                result += genResultHtml(report[i].result[j])
              }
            } else {
              result += genResultHtml(report[i].result)
            }
          }
          $('.jump').html(jump)
          $('.result').html(result)
          showResult()
        }
        else {
          $('.result').html('<div class="error">Sorry, we can not connect to this website now.</div>')
          showResult()
        }
      },
      error: function () {
        $('.result').html('<div class="error">Sorry, we can not connect to this website now.</div>')
        showResult()
      }
    })
  }
  $('select').niceSelect();
  let scheme = getQueryVariable('scheme')
  let domain = getQueryVariable('domain')
  if (scheme && domain) {
    resultPage(scheme, domain)
  }
  $('.container').removeClass('dn')
  $('#submit').on('click', function () {
    scan()
  })
  $(document).keyup(function (event) {
    if (event.keyCode == 13) {
      scan()
    }
  })
  $(window).on('scroll', function () {
    let st = $(document).scrollTop()
    if (st > 500) {
      if ($('#main-container').length != 0) {
        let w = $(window).width(),
          mw = $('#main-container').width()
        if ((w - mw) / 2 > 70)
          $('#go-top').css({
            'left': (w - mw) / 2 + mw + 20
          })
        else {
          $('#go-top').css({
            'left': 'auto'
          })
        }
      }
      $('#go-top').fadeIn(800, function () {
        $(this).removeClass('dn')
      })
    } else {
      $('#go-top').fadeOut(800, function () {
        $(this).addClass('dn')
      })
    }
  })
  $('#go-top .go').on('click', function () {
    $('html,body').animate({
      'scrollTop': 0
    }, 500)
  })
})