<?php

declare(strict_types=1);

namespace MoneroIntegrations\MoneroCrypto\Mnemonic;

use MoneroIntegrations\MoneroCrypto\Wordset;

class chinese_simplified implements Wordset
{
    /* Returns name of wordset in the wordset's native language.
     * This is a human-readable string, and should be capitalized
     * if the language supports it.
     */
    public static function name(): string
    {
        return "简体中文 (中国)";
    }

    /* Returns name of wordset in english.
     * This is a human-readable string, and should be capitalized
     */
    public static function englishName(): string
    {
        return "Chinese (simplified)";
    }

    /* Returns integer indicating length of unique prefix,
     * such that each prefix of this length is unique across
     * the entire set of words.
     *
     * A value of 0 indicates that there is no unique prefix
     * and the entire word must be used instead.
     */
    public static function prefixLength(): int
    {
        return 1;  // first letter of each word in wordset is unique.
    }

    /* Returns an array of all words in the wordset.
     */
    public static function words(): array
    {
        return [
            "的",
            "一",
            "是",
            "在",
            "不",
            "了",
            "有",
            "和",
            "人",
            "这",
            "中",
            "大",
            "为",
            "上",
            "个",
            "国",
            "我",
            "以",
            "要",
            "他",
            "时",
            "来",
            "用",
            "们",
            "生",
            "到",
            "作",
            "地",
            "于",
            "出",
            "就",
            "分",
            "对",
            "成",
            "会",
            "可",
            "主",
            "发",
            "年",
            "动",
            "同",
            "工",
            "也",
            "能",
            "下",
            "过",
            "子",
            "说",
            "产",
            "种",
            "面",
            "而",
            "方",
            "后",
            "多",
            "定",
            "行",
            "学",
            "法",
            "所",
            "民",
            "得",
            "经",
            "十",
            "三",
            "之",
            "进",
            "着",
            "等",
            "部",
            "度",
            "家",
            "电",
            "力",
            "里",
            "如",
            "水",
            "化",
            "高",
            "自",
            "二",
            "理",
            "起",
            "小",
            "物",
            "现",
            "实",
            "加",
            "量",
            "都",
            "两",
            "体",
            "制",
            "机",
            "当",
            "使",
            "点",
            "从",
            "业",
            "本",
            "去",
            "把",
            "性",
            "好",
            "应",
            "开",
            "它",
            "合",
            "还",
            "因",
            "由",
            "其",
            "些",
            "然",
            "前",
            "外",
            "天",
            "政",
            "四",
            "日",
            "那",
            "社",
            "义",
            "事",
            "平",
            "形",
            "相",
            "全",
            "表",
            "间",
            "样",
            "与",
            "关",
            "各",
            "重",
            "新",
            "线",
            "内",
            "数",
            "正",
            "心",
            "反",
            "你",
            "明",
            "看",
            "原",
            "又",
            "么",
            "利",
            "比",
            "或",
            "但",
            "质",
            "气",
            "第",
            "向",
            "道",
            "命",
            "此",
            "变",
            "条",
            "只",
            "没",
            "结",
            "解",
            "问",
            "意",
            "建",
            "月",
            "公",
            "无",
            "系",
            "军",
            "很",
            "情",
            "者",
            "最",
            "立",
            "代",
            "想",
            "已",
            "通",
            "并",
            "提",
            "直",
            "题",
            "党",
            "程",
            "展",
            "五",
            "果",
            "料",
            "象",
            "员",
            "革",
            "位",
            "入",
            "常",
            "文",
            "总",
            "次",
            "品",
            "式",
            "活",
            "设",
            "及",
            "管",
            "特",
            "件",
            "长",
            "求",
            "老",
            "头",
            "基",
            "资",
            "边",
            "流",
            "路",
            "级",
            "少",
            "图",
            "山",
            "统",
            "接",
            "知",
            "较",
            "将",
            "组",
            "见",
            "计",
            "别",
            "她",
            "手",
            "角",
            "期",
            "根",
            "论",
            "运",
            "农",
            "指",
            "几",
            "九",
            "区",
            "强",
            "放",
            "决",
            "西",
            "被",
            "干",
            "做",
            "必",
            "战",
            "先",
            "回",
            "则",
            "任",
            "取",
            "据",
            "处",
            "队",
            "南",
            "给",
            "色",
            "光",
            "门",
            "即",
            "保",
            "治",
            "北",
            "造",
            "百",
            "规",
            "热",
            "领",
            "七",
            "海",
            "口",
            "东",
            "导",
            "器",
            "压",
            "志",
            "世",
            "金",
            "增",
            "争",
            "济",
            "阶",
            "油",
            "思",
            "术",
            "极",
            "交",
            "受",
            "联",
            "什",
            "认",
            "六",
            "共",
            "权",
            "收",
            "证",
            "改",
            "清",
            "美",
            "再",
            "采",
            "转",
            "更",
            "单",
            "风",
            "切",
            "打",
            "白",
            "教",
            "速",
            "花",
            "带",
            "安",
            "场",
            "身",
            "车",
            "例",
            "真",
            "务",
            "具",
            "万",
            "每",
            "目",
            "至",
            "达",
            "走",
            "积",
            "示",
            "议",
            "声",
            "报",
            "斗",
            "完",
            "类",
            "八",
            "离",
            "华",
            "名",
            "确",
            "才",
            "科",
            "张",
            "信",
            "马",
            "节",
            "话",
            "米",
            "整",
            "空",
            "元",
            "况",
            "今",
            "集",
            "温",
            "传",
            "土",
            "许",
            "步",
            "群",
            "广",
            "石",
            "记",
            "需",
            "段",
            "研",
            "界",
            "拉",
            "林",
            "律",
            "叫",
            "且",
            "究",
            "观",
            "越",
            "织",
            "装",
            "影",
            "算",
            "低",
            "持",
            "音",
            "众",
            "书",
            "布",
            "复",
            "容",
            "儿",
            "须",
            "际",
            "商",
            "非",
            "验",
            "连",
            "断",
            "深",
            "难",
            "近",
            "矿",
            "千",
            "周",
            "委",
            "素",
            "技",
            "备",
            "半",
            "办",
            "青",
            "省",
            "列",
            "习",
            "响",
            "约",
            "支",
            "般",
            "史",
            "感",
            "劳",
            "便",
            "团",
            "往",
            "酸",
            "历",
            "市",
            "克",
            "何",
            "除",
            "消",
            "构",
            "府",
            "称",
            "太",
            "准",
            "精",
            "值",
            "号",
            "率",
            "族",
            "维",
            "划",
            "选",
            "标",
            "写",
            "存",
            "候",
            "毛",
            "亲",
            "快",
            "效",
            "斯",
            "院",
            "查",
            "江",
            "型",
            "眼",
            "王",
            "按",
            "格",
            "养",
            "易",
            "置",
            "派",
            "层",
            "片",
            "始",
            "却",
            "专",
            "状",
            "育",
            "厂",
            "京",
            "识",
            "适",
            "属",
            "圆",
            "包",
            "火",
            "住",
            "调",
            "满",
            "县",
            "局",
            "照",
            "参",
            "红",
            "细",
            "引",
            "听",
            "该",
            "铁",
            "价",
            "严",
            "首",
            "底",
            "液",
            "官",
            "德",
            "随",
            "病",
            "苏",
            "失",
            "尔",
            "死",
            "讲",
            "配",
            "女",
            "黄",
            "推",
            "显",
            "谈",
            "罪",
            "神",
            "艺",
            "呢",
            "席",
            "含",
            "企",
            "望",
            "密",
            "批",
            "营",
            "项",
            "防",
            "举",
            "球",
            "英",
            "氧",
            "势",
            "告",
            "李",
            "台",
            "落",
            "木",
            "帮",
            "轮",
            "破",
            "亚",
            "师",
            "围",
            "注",
            "远",
            "字",
            "材",
            "排",
            "供",
            "河",
            "态",
            "封",
            "另",
            "施",
            "减",
            "树",
            "溶",
            "怎",
            "止",
            "案",
            "言",
            "士",
            "均",
            "武",
            "固",
            "叶",
            "鱼",
            "波",
            "视",
            "仅",
            "费",
            "紧",
            "爱",
            "左",
            "章",
            "早",
            "朝",
            "害",
            "续",
            "轻",
            "服",
            "试",
            "食",
            "充",
            "兵",
            "源",
            "判",
            "护",
            "司",
            "足",
            "某",
            "练",
            "差",
            "致",
            "板",
            "田",
            "降",
            "黑",
            "犯",
            "负",
            "击",
            "范",
            "继",
            "兴",
            "似",
            "余",
            "坚",
            "曲",
            "输",
            "修",
            "故",
            "城",
            "夫",
            "够",
            "送",
            "笔",
            "船",
            "占",
            "右",
            "财",
            "吃",
            "富",
            "春",
            "职",
            "觉",
            "汉",
            "画",
            "功",
            "巴",
            "跟",
            "虽",
            "杂",
            "飞",
            "检",
            "吸",
            "助",
            "升",
            "阳",
            "互",
            "初",
            "创",
            "抗",
            "考",
            "投",
            "坏",
            "策",
            "古",
            "径",
            "换",
            "未",
            "跑",
            "留",
            "钢",
            "曾",
            "端",
            "责",
            "站",
            "简",
            "述",
            "钱",
            "副",
            "尽",
            "帝",
            "射",
            "草",
            "冲",
            "承",
            "独",
            "令",
            "限",
            "阿",
            "宣",
            "环",
            "双",
            "请",
            "超",
            "微",
            "让",
            "控",
            "州",
            "良",
            "轴",
            "找",
            "否",
            "纪",
            "益",
            "依",
            "优",
            "顶",
            "础",
            "载",
            "倒",
            "房",
            "突",
            "坐",
            "粉",
            "敌",
            "略",
            "客",
            "袁",
            "冷",
            "胜",
            "绝",
            "析",
            "块",
            "剂",
            "测",
            "丝",
            "协",
            "诉",
            "念",
            "陈",
            "仍",
            "罗",
            "盐",
            "友",
            "洋",
            "错",
            "苦",
            "夜",
            "刑",
            "移",
            "频",
            "逐",
            "靠",
            "混",
            "母",
            "短",
            "皮",
            "终",
            "聚",
            "汽",
            "村",
            "云",
            "哪",
            "既",
            "距",
            "卫",
            "停",
            "烈",
            "央",
            "察",
            "烧",
            "迅",
            "境",
            "若",
            "印",
            "洲",
            "刻",
            "括",
            "激",
            "孔",
            "搞",
            "甚",
            "室",
            "待",
            "核",
            "校",
            "散",
            "侵",
            "吧",
            "甲",
            "游",
            "久",
            "菜",
            "味",
            "旧",
            "模",
            "湖",
            "货",
            "损",
            "预",
            "阻",
            "毫",
            "普",
            "稳",
            "乙",
            "妈",
            "植",
            "息",
            "扩",
            "银",
            "语",
            "挥",
            "酒",
            "守",
            "拿",
            "序",
            "纸",
            "医",
            "缺",
            "雨",
            "吗",
            "针",
            "刘",
            "啊",
            "急",
            "唱",
            "误",
            "训",
            "愿",
            "审",
            "附",
            "获",
            "茶",
            "鲜",
            "粮",
            "斤",
            "孩",
            "脱",
            "硫",
            "肥",
            "善",
            "龙",
            "演",
            "父",
            "渐",
            "血",
            "欢",
            "械",
            "掌",
            "歌",
            "沙",
            "刚",
            "攻",
            "谓",
            "盾",
            "讨",
            "晚",
            "粒",
            "乱",
            "燃",
            "矛",
            "乎",
            "杀",
            "药",
            "宁",
            "鲁",
            "贵",
            "钟",
            "煤",
            "读",
            "班",
            "伯",
            "香",
            "介",
            "迫",
            "句",
            "丰",
            "培",
            "握",
            "兰",
            "担",
            "弦",
            "蛋",
            "沉",
            "假",
            "穿",
            "执",
            "答",
            "乐",
            "谁",
            "顺",
            "烟",
            "缩",
            "征",
            "脸",
            "喜",
            "松",
            "脚",
            "困",
            "异",
            "免",
            "背",
            "星",
            "福",
            "买",
            "染",
            "井",
            "概",
            "慢",
            "怕",
            "磁",
            "倍",
            "祖",
            "皇",
            "促",
            "静",
            "补",
            "评",
            "翻",
            "肉",
            "践",
            "尼",
            "衣",
            "宽",
            "扬",
            "棉",
            "希",
            "伤",
            "操",
            "垂",
            "秋",
            "宜",
            "氢",
            "套",
            "督",
            "振",
            "架",
            "亮",
            "末",
            "宪",
            "庆",
            "编",
            "牛",
            "触",
            "映",
            "雷",
            "销",
            "诗",
            "座",
            "居",
            "抓",
            "裂",
            "胞",
            "呼",
            "娘",
            "景",
            "威",
            "绿",
            "晶",
            "厚",
            "盟",
            "衡",
            "鸡",
            "孙",
            "延",
            "危",
            "胶",
            "屋",
            "乡",
            "临",
            "陆",
            "顾",
            "掉",
            "呀",
            "灯",
            "岁",
            "措",
            "束",
            "耐",
            "剧",
            "玉",
            "赵",
            "跳",
            "哥",
            "季",
            "课",
            "凯",
            "胡",
            "额",
            "款",
            "绍",
            "卷",
            "齐",
            "伟",
            "蒸",
            "殖",
            "永",
            "宗",
            "苗",
            "川",
            "炉",
            "岩",
            "弱",
            "零",
            "杨",
            "奏",
            "沿",
            "露",
            "杆",
            "探",
            "滑",
            "镇",
            "饭",
            "浓",
            "航",
            "怀",
            "赶",
            "库",
            "夺",
            "伊",
            "灵",
            "税",
            "途",
            "灭",
            "赛",
            "归",
            "召",
            "鼓",
            "播",
            "盘",
            "裁",
            "险",
            "康",
            "唯",
            "录",
            "菌",
            "纯",
            "借",
            "糖",
            "盖",
            "横",
            "符",
            "私",
            "努",
            "堂",
            "域",
            "枪",
            "润",
            "幅",
            "哈",
            "竟",
            "熟",
            "虫",
            "泽",
            "脑",
            "壤",
            "碳",
            "欧",
            "遍",
            "侧",
            "寨",
            "敢",
            "彻",
            "虑",
            "斜",
            "薄",
            "庭",
            "纳",
            "弹",
            "饲",
            "伸",
            "折",
            "麦",
            "湿",
            "暗",
            "荷",
            "瓦",
            "塞",
            "床",
            "筑",
            "恶",
            "户",
            "访",
            "塔",
            "奇",
            "透",
            "梁",
            "刀",
            "旋",
            "迹",
            "卡",
            "氯",
            "遇",
            "份",
            "毒",
            "泥",
            "退",
            "洗",
            "摆",
            "灰",
            "彩",
            "卖",
            "耗",
            "夏",
            "择",
            "忙",
            "铜",
            "献",
            "硬",
            "予",
            "繁",
            "圈",
            "雪",
            "函",
            "亦",
            "抽",
            "篇",
            "阵",
            "阴",
            "丁",
            "尺",
            "追",
            "堆",
            "雄",
            "迎",
            "泛",
            "爸",
            "楼",
            "避",
            "谋",
            "吨",
            "野",
            "猪",
            "旗",
            "累",
            "偏",
            "典",
            "馆",
            "索",
            "秦",
            "脂",
            "潮",
            "爷",
            "豆",
            "忽",
            "托",
            "惊",
            "塑",
            "遗",
            "愈",
            "朱",
            "替",
            "纤",
            "粗",
            "倾",
            "尚",
            "痛",
            "楚",
            "谢",
            "奋",
            "购",
            "磨",
            "君",
            "池",
            "旁",
            "碎",
            "骨",
            "监",
            "捕",
            "弟",
            "暴",
            "割",
            "贯",
            "殊",
            "释",
            "词",
            "亡",
            "壁",
            "顿",
            "宝",
            "午",
            "尘",
            "闻",
            "揭",
            "炮",
            "残",
            "冬",
            "桥",
            "妇",
            "警",
            "综",
            "招",
            "吴",
            "付",
            "浮",
            "遭",
            "徐",
            "您",
            "摇",
            "谷",
            "赞",
            "箱",
            "隔",
            "订",
            "男",
            "吹",
            "园",
            "纷",
            "唐",
            "败",
            "宋",
            "玻",
            "巨",
            "耕",
            "坦",
            "荣",
            "闭",
            "湾",
            "键",
            "凡",
            "驻",
            "锅",
            "救",
            "恩",
            "剥",
            "凝",
            "碱",
            "齿",
            "截",
            "炼",
            "麻",
            "纺",
            "禁",
            "废",
            "盛",
            "版",
            "缓",
            "净",
            "睛",
            "昌",
            "婚",
            "涉",
            "筒",
            "嘴",
            "插",
            "岸",
            "朗",
            "庄",
            "街",
            "藏",
            "姑",
            "贸",
            "腐",
            "奴",
            "啦",
            "惯",
            "乘",
            "伙",
            "恢",
            "匀",
            "纱",
            "扎",
            "辩",
            "耳",
            "彪",
            "臣",
            "亿",
            "璃",
            "抵",
            "脉",
            "秀",
            "萨",
            "俄",
            "网",
            "舞",
            "店",
            "喷",
            "纵",
            "寸",
            "汗",
            "挂",
            "洪",
            "贺",
            "闪",
            "柬",
            "爆",
            "烯",
            "津",
            "稻",
            "墙",
            "软",
            "勇",
            "像",
            "滚",
            "厘",
            "蒙",
            "芳",
            "肯",
            "坡",
            "柱",
            "荡",
            "腿",
            "仪",
            "旅",
            "尾",
            "轧",
            "冰",
            "贡",
            "登",
            "黎",
            "削",
            "钻",
            "勒",
            "逃",
            "障",
            "氨",
            "郭",
            "峰",
            "币",
            "港",
            "伏",
            "轨",
            "亩",
            "毕",
            "擦",
            "莫",
            "刺",
            "浪",
            "秘",
            "援",
            "株",
            "健",
            "售",
            "股",
            "岛",
            "甘",
            "泡",
            "睡",
            "童",
            "铸",
            "汤",
            "阀",
            "休",
            "汇",
            "舍",
            "牧",
            "绕",
            "炸",
            "哲",
            "磷",
            "绩",
            "朋",
            "淡",
            "尖",
            "启",
            "陷",
            "柴",
            "呈",
            "徒",
            "颜",
            "泪",
            "稍",
            "忘",
            "泵",
            "蓝",
            "拖",
            "洞",
            "授",
            "镜",
            "辛",
            "壮",
            "锋",
            "贫",
            "虚",
            "弯",
            "摩",
            "泰",
            "幼",
            "廷",
            "尊",
            "窗",
            "纲",
            "弄",
            "隶",
            "疑",
            "氏",
            "宫",
            "姐",
            "震",
            "瑞",
            "怪",
            "尤",
            "琴",
            "循",
            "描",
            "膜",
            "违",
            "夹",
            "腰",
            "缘",
            "珠",
            "穷",
            "森",
            "枝",
            "竹",
            "沟",
            "催",
            "绳",
            "忆",
            "邦",
            "剩",
            "幸",
            "浆",
            "栏",
            "拥",
            "牙",
            "贮",
            "礼",
            "滤",
            "钠",
            "纹",
            "罢",
            "拍",
            "咱",
            "喊",
            "袖",
            "埃",
            "勤",
            "罚",
            "焦",
            "潜",
            "伍",
            "墨",
            "欲",
            "缝",
            "姓",
            "刊",
            "饱",
            "仿",
            "奖",
            "铝",
            "鬼",
            "丽",
            "跨",
            "默",
            "挖",
            "链",
            "扫",
            "喝",
            "袋",
            "炭",
            "污",
            "幕",
            "诸",
            "弧",
            "励",
            "梅",
            "奶",
            "洁",
            "灾",
            "舟",
            "鉴",
            "苯",
            "讼",
            "抱",
            "毁",
            "懂",
            "寒",
            "智",
            "埔",
            "寄",
            "届",
            "跃",
            "渡",
            "挑",
            "丹",
            "艰",
            "贝",
            "碰",
            "拔",
            "爹",
            "戴",
            "码",
            "梦",
            "芽",
            "熔",
            "赤",
            "渔",
            "哭",
            "敬",
            "颗",
            "奔",
            "铅",
            "仲",
            "虎",
            "稀",
            "妹",
            "乏",
            "珍",
            "申",
            "桌",
            "遵",
            "允",
            "隆",
            "螺",
            "仓",
            "魏",
            "锐",
            "晓",
            "氮",
            "兼",
            "隐",
            "碍",
            "赫",
            "拨",
            "忠",
            "肃",
            "缸",
            "牵",
            "抢",
            "博",
            "巧",
            "壳",
            "兄",
            "杜",
            "讯",
            "诚",
            "碧",
            "祥",
            "柯",
            "页",
            "巡",
            "矩",
            "悲",
            "灌",
            "龄",
            "伦",
            "票",
            "寻",
            "桂",
            "铺",
            "圣",
            "恐",
            "恰",
            "郑",
            "趣",
            "抬",
            "荒",
            "腾",
            "贴",
            "柔",
            "滴",
            "猛",
            "阔",
            "辆",
            "妻",
            "填",
            "撤",
            "储",
            "签",
            "闹",
            "扰",
            "紫",
            "砂",
            "递",
            "戏",
            "吊",
            "陶",
            "伐",
            "喂",
            "疗",
            "瓶",
            "婆",
            "抚",
            "臂",
            "摸",
            "忍",
            "虾",
            "蜡",
            "邻",
            "胸",
            "巩",
            "挤",
            "偶",
            "弃",
            "槽",
            "劲",
            "乳",
            "邓",
            "吉",
            "仁",
            "烂",
            "砖",
            "租",
            "乌",
            "舰",
            "伴",
            "瓜",
            "浅",
            "丙",
            "暂",
            "燥",
            "橡",
            "柳",
            "迷",
            "暖",
            "牌",
            "秧",
            "胆",
            "详",
            "簧",
            "踏",
            "瓷",
            "谱",
            "呆",
            "宾",
            "糊",
            "洛",
            "辉",
            "愤",
            "竞",
            "隙",
            "怒",
            "粘",
            "乃",
            "绪",
            "肩",
            "籍",
            "敏",
            "涂",
            "熙",
            "皆",
            "侦",
            "悬",
            "掘",
            "享",
            "纠",
            "醒",
            "狂",
            "锁",
            "淀",
            "恨",
            "牲",
            "霸",
            "爬",
            "赏",
            "逆",
            "玩",
            "陵",
            "祝",
            "秒",
            "浙",
            "貌",
        ];
    }
}
