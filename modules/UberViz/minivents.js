function Events(e){var t={},n,r,i,s=Array;e=e||this;e.on=function(e,n,r){t[e]||(t[e]=[]);t[e].push({f:n,c:r})};e.off=function(e,i){r=t[e]||[];n=r.length=i?r.length:0;while(~--n<0)i===r[n].f&&r.splice(n,1)};e.emit=function(){i=s.apply([],arguments);r=t[i.shift()]||[];i=i[0]instanceof s&&i[0]||i;n=r.length;while(~--n<0)r[n].f.apply(r[n].c,i)}}
