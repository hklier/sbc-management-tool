'use strict';
let diagnosticHistory=[],diagnosticHistoryHost='';
const diagnosticChartColors={cpu:'#087f72',memory:'#5579b8',sessions:'#a56815'};
function diagnosticNumber(section,name,percent=false){const raw=diagnosticValue(section,name);if(raw===undefined||raw===null||raw==='')return null;const value=Number(raw);return Number.isFinite(value)&&value>=0&&(!percent||value<=100)?value:null}
function diagnosticSvg(tag,attributes={},value){const node=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,item]of Object.entries(attributes))node.setAttribute(key,String(item));if(value!==undefined)node.textContent=value;return node}
function resetDiagnosticCharts(){diagnosticHistory=[];diagnosticHistoryHost=''}
function diagnosticRing(label,value,color){
  const box=el('div',{class:'diagnostic-ring'}),svg=diagnosticSvg('svg',{viewBox:'0 0 180 150',role:'img','aria-label':label+': '+(value===null?'unavailable':value+'%')});
  svg.append(diagnosticSvg('circle',{cx:90,cy:68,r:48,fill:'none',stroke:'#e6eeec','stroke-width':12}));
  if(value!==null)svg.append(diagnosticSvg('circle',{cx:90,cy:68,r:48,fill:'none',stroke:color,'stroke-width':12,'stroke-dasharray':(value/100*301.593)+' 301.593',transform:'rotate(-90 90 68)'}));
  svg.append(diagnosticSvg('text',{x:90,y:75,'text-anchor':'middle',class:'chart-ring-value'},value===null?'—':value+'%'),diagnosticSvg('text',{x:90,y:142,'text-anchor':'middle',class:'chart-ring-label'},label));box.append(svg);return box
}
function diagnosticLineChart(title,series,percent=false,samples=diagnosticHistory){
  const card=el('section',{class:'diagnostic-line-card'});card.append(el('h3',{},title));
  const legend=el('div',{class:'diagnostic-chart-legend'});series.forEach(s=>{const item=el('span',{'data-series':s.key},s.label);legend.append(item)});card.append(legend);
  const svg=diagnosticSvg('svg',{viewBox:'0 0 560 220',role:'img','aria-label':title+' over time'}),left=48,top=14,width=490,height=158;
  const valid=samples.flatMap(sample=>series.map(s=>sample[s.key]).filter(v=>v!==null));
  const max=percent?100:Math.max(4,Math.ceil(Math.max(0,...valid)/4)*4),start=samples[0]?.time||0,end=samples.at(-1)?.time||start;
  const x=time=>end===start?left+width/2:left+(time-start)/(end-start)*width,y=value=>top+height-value/max*height;
  for(let i=0;i<=4;i++){const value=max*i/4,yy=y(value);svg.append(diagnosticSvg('line',{x1:left,y1:yy,x2:left+width,y2:yy,stroke:'#e5eeeb'}),diagnosticSvg('text',{x:left-8,y:yy+4,'text-anchor':'end',class:'chart-axis'},percent?value+'%':Number(value.toFixed(2)).toString()))}
  series.forEach(s=>{let points=[],last=null;const flush=()=>{if(points.length)svg.append(diagnosticSvg('polyline',{points:points.join(' '),fill:'none',stroke:s.color,'stroke-width':2}));points=[]};
    for(const sample of samples){const value=sample[s.key];if(value===null||last!==null&&sample.time-last>90000)flush();if(value!==null){points.push(x(sample.time)+','+y(value));const point=diagnosticSvg('circle',{cx:x(sample.time),cy:y(value),r:3,fill:s.color});point.append(diagnosticSvg('title',{},new Date(sample.time).toLocaleTimeString('en-GB')+' · '+s.label+': '+value+(percent?'%':'')));svg.append(point)}last=sample.time}flush()
  });
  if(samples.length){const format=t=>new Date(t).toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'});svg.append(diagnosticSvg('text',{x:left,y:198,class:'chart-axis'},format(start)),diagnosticSvg('text',{x:left+width,y:198,'text-anchor':'end',class:'chart-axis'},format(end)))}
  card.append(svg);if(!valid.length)card.append(el('p',{class:'muted'},'No measurements available.'));else if(samples.length<2)card.append(el('p',{class:'muted'},'First measurement. Refresh again to show the trend.'));return card
}
function renderDiagnosticCharts(data){
  if(diagnosticHistoryHost!==data.host){resetDiagnosticCharts();diagnosticHistoryHost=data.host}
  const s=data.sections,sample={time:Date.parse(data.checkedAt),cpu:diagnosticNumber(s.sysCPUUtil,'sysCPUUtilPercent.percentUsed',true),memory:diagnosticNumber(s.sysMemoryUtil,'sysMemoryUtil.percentUsed',true),sessions:diagnosticNumber(s.globalSessions,'globalSessions.sysGlobalConSessions'),cps:diagnosticNumber(s.globalSessions,'globalSessions.sysGlobalCPS')};
  if(Number.isFinite(sample.time)){if(diagnosticHistory.at(-1)?.time===sample.time)diagnosticHistory[diagnosticHistory.length-1]=sample;else if(!diagnosticHistory.length||sample.time>diagnosticHistory.at(-1).time)diagnosticHistory.push(sample);diagnosticHistory=diagnosticHistory.slice(-180)}
  data.chartSamples=diagnosticHistory.map(item=>({...item}));
  $('diagnostics-rings').replaceChildren(diagnosticRing('CPU utilization',sample.cpu,diagnosticChartColors.cpu),diagnosticRing('Memory utilization',sample.memory,diagnosticChartColors.memory),diagnosticRing('Health score',diagnosticNumber(s.system,'healthScorePercent',true),'#25804e'));
  $('diagnostics-trends').replaceChildren(diagnosticLineChart('CPU & memory',[{key:'cpu',label:'CPU',color:diagnosticChartColors.cpu},{key:'memory',label:'Memory',color:diagnosticChartColors.memory}],true),diagnosticLineChart('Concurrent sessions',[{key:'sessions',label:'Sessions',color:diagnosticChartColors.sessions}]),diagnosticLineChart('Calls per second',[{key:'cps',label:'CPS',color:diagnosticChartColors.cpu}]));
  $('diagnostics-chart-note').textContent=diagnosticHistory.length+' measurement'+(diagnosticHistory.length===1?'':'s')+' collected in this tab. Enable automatic refresh to follow the trend. Up to 180 measurements are retained; missing values and pauses appear as gaps.';
}
