__int64 __fastcall _LSLaunchWithRunningboard(
        LSContext *a1,
        void *a2,
        unsigned int a3,
        void *a4,
        void *a5,
        const AEDesc *a6,
        const AEDesc *a7,
        void *a8,
        const __CFDictionary *a9,
        unsigned int a10,
        const audit_token_t *a11,
        void *a12,
        __int64 a13,
        NSError **a14)
{
  os_log_s *v17; // x22
  int v18; // w21
  const char *v19; // x24
  __CFString *v20; // x19
  __CFString *v21; // x27
  __CFString *v22; // x21
  __CFString *v23; // x28
  __CFString *v24; // x25
  __CFString *v25; // x23
  __CFString *v26; // x26
  int v27; // w19
  id v28; // x0
  __int64 v29; // x9
  int v30; // w8
  __int64 v31; // x22
  NSString *v32; // x20
  const LSBundleData *v33; // x0
  id v34; // x24
  NSString *v35; // x22
  char *v36; // x25
  id v37; // x26
  char *v38; // x0
  char *v39; // x27
  _BOOL4 v40; // w19
  size_t v41; // x0
  os_log_s *v42; // x20
  void *v43; // x22
  int v44; // w8
  id v45; // x24
  unsigned __int8 v46; // w0
  int v47; // w21
  NSDictionary *v48; // x22
  id v49; // x20
  dispatch_queue_global_s *v50; // x19
  os_log_s *v51; // x20
  id v52; // x19
  int v53; // w8
  os_log_s *v54; // x20
  id v55; // x22
  void *v56; // x24
  int v57; // w8
  __int64 v58; // x22
  id v59; // x24
  id v60; // x26
  int v61; // w20
  __int64 v62; // x0
  __int64 v63; // x20
  id v64; // x28
  __int128 v65; // q1
  __int128 v66; // q1
  __int128 v67; // q1
  __int128 v68; // q1
  __int128 v69; // q0
  os_log_s *v70; // x22
  os_log_s *v71; // x22
  __int64 v72; // x8
  id v73; // x22
  LSSliceInfo *v74; // x25
  unsigned __int8 v75; // w19
  id v76; // x19
  NSMutableSet *v77; // x25
  id v78; // x21
  NSMutableSet *v79; // x25
  NSArray *v80; // x27
  NSUInteger v81; // x19
  os_log_s *v82; // x22
  os_log_s *v83; // x0
  os_log_s *v84; // x20
  void *v85; // x22
  id v86; // x20
  const char *v87; // x3
  int v88; // w19
  os_log_s *v89; // x21
  id v90; // x25
  id v91; // x22
  void *v92; // x27
  const char *v93; // x3
  os_log_s *v94; // x1
  uint32_t v95; // w5
  os_log_s *v96; // x20
  void *v97; // x22
  id v98; // x20
  void *v99; // x22
  const char *v100; // x3
  os_log_s *v101; // x22
  id v102; // x20
  id v103; // x25
  void *v104; // x27
  os_log_s *v105; // x0
  __int64 v106; // x26
  id v107; // x24
  char v108; // w19
  id v109; // x0
  void *v110; // x22
  int v111; // w20
  __int64 v112; // x0
  os_log_s *v113; // x25
  id v114; // x26
  void *v115; // x27
  NSError *v116; // x22
  __int64 v117; // x0
  os_log_s *v118; // x20
  id v119; // x25
  void *v120; // x24
  os_log_s *v121; // x20
  void *v122; // x25
  void *v123; // x26
  __int64 v124; // x19
  id v125; // x24
  __int64 v126; // x0
  int v127; // w25
  __int64 v128; // x0
  os_log_s *v129; // x20
  os_log_s *v130; // x0
  NSString *v131; // x20
  NSError *v132; // x22
  __int64 v133; // x0
  os_log_s *v134; // x20
  void *v135; // x24
  int v136; // w0
  id v137; // x0
  void *v138; // x24
  void *v139; // x20
  const __CFArray *v140; // x0
  const __CFArray *v141; // x25
  const __CFArray *v142; // x22
  int v143; // w8
  void *v144; // x22
  void *v145; // x19
  id v146; // x22
  __int64 SPExecutionPolicyClass; // x0
  void *v148; // x24
  __int64 v149; // x20
  id v150; // x25
  os_log_s *v151; // x26
  unsigned int v152; // w19
  id v153; // x0
  void *v154; // x26
  os_log_s *v155; // x20
  void *v156; // x25
  const char *v157; // x3
  os_log_s *v158; // x1
  os_log_type_t v159; // w2
  uint32_t v160; // w5
  __LSASN *v161; // x24
  _LSPlistHint *v162; // x3
  __int64 v163; // x2
  id v164; // x19
  __int64 v165; // x25
  NSString *v166; // x22
  NSString *v167; // x27
  NSString *v168; // x20
  const __CFArray *v169; // x0
  const __CFArray *v170; // x24
  const void *v171; // x0
  const void *v172; // x20
  const void *v173; // x8
  const void *v174; // x24
  CFTypeID TypeID; // x19
  int v176; // w19
  __int64 v177; // x0
  os_log_s *v178; // x24
  int v179; // w19
  __int64 v180; // x0
  os_log_s *v181; // x20
  int v182; // w19
  NSObject *v183; // x27
  _LSPlistHint *v184; // x3
  __int64 isKindOfClass_2; // x0
  void *v186; // x26
  __int64 v187; // x0
  void *v188; // x20
  int v189; // w19
  NSError *v190; // x28
  __int64 v191; // x0
  __int64 v192; // x0
  id v193; // x0
  id v194; // x21
  os_log_s *v195; // x19
  CFIndex Count; // x26
  CFIndex v197; // x27
  bool v198; // w21
  const void *ValueAtIndex; // x25
  int v200; // w19
  const void *v201; // x0
  const __CFNumber *v202; // x0
  const __CFNumber *v203; // x25
  int Value; // w19
  int v205; // w21
  int v206; // w0
  int v207; // w8
  __int64 v208; // x0
  os_log_s *v209; // x20
  id v210; // x22
  void *v211; // x25
  __int64 v212; // x0
  os_log_s *v213; // x20
  int v214; // w19
  const char *v215; // x3
  os_log_s *v216; // x1
  os_log_type_t v217; // w2
  uint32_t v218; // w5
  const void *v219; // x0
  __int64 v220; // x0
  int v221; // w19
  int v222; // w8
  __int128 v223; // q1
  unsigned __int64 MajorComponent; // x8
  const __LSASN *v225; // x0
  const void *v226; // x20
  const void *v227; // x24
  unsigned __int64 v228; // x0
  const void *v229; // x0
  int v230; // w19
  const void *v231; // x0
  __int64 v232; // x0
  const void *v233; // x0
  __int64 v234; // x0
  int v235; // w19
  const void *v236; // x22
  CFTypeID v237; // x19
  __int64 v238; // x0
  int v239; // w19
  os_log_s *v240; // x20
  int v241; // w19
  __int64 v242; // x0
  os_log_s *v243; // x20
  NSObject *v244; // x0
  __int64 v245; // x0
  const _LSOpen2Options *v246; // x2
  int v247; // w8
  __int64 v248; // x28
  os_log_s *v249; // x19
  void *v250; // x20
  __int64 v251; // x26
  id v252; // x19
  const __LSASN *v253; // x0
  __LSASN *v254; // x27
  unsigned __int8 v255; // w20
  const __LSASN *v256; // x19
  NSNumber *v257; // x20
  NSNumber *v258; // x20
  NSNumber *v259; // x19
  NSNumber *v260; // x19
  NSNumber *v261; // x19
  void *v262; // x19
  int v263; // w0
  void *v264; // x19
  int v265; // w0
  void *v266; // x19
  id v267; // x19
  __CFString **v268; // x8
  __int64 v269; // x8
  NSNumber *v270; // x19
  __int64 v271; // x0
  os_log_s *v272; // x19
  NSNumber *v273; // x20
  NSURL *v274; // x19
  NSNumber *v275; // x21
  int IsAppManagedAtURL; // w20
  __int64 v277; // x0
  os_log_s *v278; // x19
  NSURL *v279; // x0
  NSURL *v280; // x20
  void *v281; // x26
  __int64 v282; // x21
  void *j; // x28
  id v284; // x20
  void *v285; // x0
  void *v286; // x22
  unsigned int v287; // w25
  __int64 v288; // x0
  NSNumber *v289; // x19
  os_log_s *v290; // x20
  os_log_s *v291; // x19
  void *v292; // x20
  NSString *v293; // x19
  unsigned int v294; // w0
  os_log_s *v295; // x20
  void *v296; // x25
  __int64 v297; // x0
  __int64 v298; // x0
  void *v299; // x0
  os_log_s *v300; // x20
  char v301; // w19
  os_log_s *v302; // x20
  int v303; // w19
  os_log_s *v304; // x26
  __int64 v305; // x0
  os_log_s *v306; // x20
  const _LSOpen2Options *v307; // x2
  void *v308; // x19
  bool v309; // zf
  int v310; // w23
  id v311; // x20
  NSString *v312; // x19
  NSString *v313; // x20
  id v314; // x22
  unsigned __int8 v315; // w25
  id v316; // x20
  NSString *v317; // x20
  NSString *v318; // x0
  NSString *v319; // x19
  NSString *v320; // x0
  NSString *v321; // x19
  __CFString *v322; // x2
  void *v323; // x0
  int v324; // w25
  __int64 v325; // x8
  os_log_s *v326; // x19
  NSDictionary *v327; // x22
  id v328; // x26
  void *v329; // x19
  NSNumber *v330; // x19
  NSNumber *v331; // x19
  __CFBundle *v332; // x0
  __CFBundle *v333; // x20
  CFURLRef v334; // x25
  FSNode *v335; // x19
  id v336; // x20
  NSNumber *v337; // x20
  NSNumber *v338; // x20
  void *v339; // x0
  os_log_s *v340; // x19
  void *v341; // x0
  os_log_s *v342; // x19
  id v343; // x20
  id v344; // x22
  NSMutableArray *v345; // x23
  __int64 v346; // x26
  id v347; // x0
  void *v348; // x22
  NSMutableArray *v349; // x19
  int v350; // w19
  void *v351; // x27
  id v352; // x20
  id v353; // x27
  NSMutableArray *v354; // x0
  NSMutableArray *v355; // x25
  NSMutableArray *v356; // x27
  NSMutableArray *v357; // x19
  void *v358; // x20
  __int64 v359; // x23
  void *k; // x26
  void *v361; // x25
  os_log_s *v362; // x20
  __int128 *v363; // x21
  id v364; // x25
  void *v365; // x26
  __int64 v366; // x20
  NSObject *v367; // x19
  unsigned int v368; // w22
  LSSliceInfo *v369; // x22
  NSArray *v370; // x19
  __int64 WouldBeSupportedIfCambriaWereInstalled; // x0
  char v372; // w20
  os_log_s *v373; // x22
  uint64_t v374; // x20
  id v375; // x19
  NSString *v376; // x19
  id v377; // x22
  NSString *v378; // x21
  NSDictionary *v379; // x0
  NSDictionary *v380; // x27
  const char *v381; // x0
  int v382; // w0
  int v383; // w19
  _LSPlistHint *v384; // x3
  bool v385; // w4
  __int64 v386; // x9
  int v387; // w8
  id v388; // x0
  os_log_s *v389; // x19
  os_log_s *v390; // x19
  id v391; // x26
  LaunchServices::PrefsStorage *v392; // x0
  __int64 Shared; // x0
  unsigned __int16 PointerKeysEnabledPreferenceForNode; // w20
  id v395; // x0
  void *v396; // x19
  os_log_s *v397; // x25
  id v398; // x28
  void *v399; // x26
  bool v400; // cf
  char v401; // w20
  char v402; // w23
  int v403; // w22
  NSString *v404; // x19
  NSString *v405; // x26
  __CFString *v406; // x20
  NSString *v407; // x25
  NSString *v408; // x25
  __CFString *v409; // x0
  id v410; // x0
  void *v411; // x26
  os_log_s *v412; // x19
  int v413; // w20
  NSDictionary *v414; // x27
  NSMutableDictionary *v415; // x19
  int v416; // w28
  int v417; // w22
  NSError *v418; // x0
  NSString *v419; // x19
  unsigned int v420; // w20
  NSDictionary *v421; // x20
  id v422; // x19
  void *v423; // x20
  unsigned int v424; // w25
  os_log_s *v425; // x20
  char v426; // w25
  NSString *v427; // x23
  int v428; // w21
  bool v429; // w4
  id v430; // x20
  id v431; // x22
  id v432; // x25
  NSError *v433; // x19
  NSError *v434; // x0
  NSError *v435; // x20
  NSDictionary *v436; // x19
  id v437; // x22
  void *v438; // x20
  NSString *v439; // x25
  unsigned int v440; // w26
  NSString *v441; // x20
  unsigned int v442; // w25
  NSInteger v443; // x0
  os_log_s *v444; // x19
  const char *v445; // x3
  os_log_s *v446; // x1
  uint32_t v447; // w5
  NSString *v448; // x20
  unsigned int v449; // w19
  __int64 v450; // x0
  __int64 v451; // x0
  os_log_s *v452; // x19
  int v453; // w8
  const char *v454; // x3
  int v455; // w8
  NSError *v456; // x19
  __int64 v457; // x0
  os_log_s *v458; // x20
  void *v459; // x19
  void *v460; // x20
  void *v461; // x22
  NSObject *v462; // x20
  int v463; // w19
  NSString *v464; // x0
  NSArray *v465; // x19
  id v466; // x0
  void *v467; // x20
  NSArray *v468; // x19
  NSArray *v469; // x19
  void *v470; // x19
  __int64 v471; // x0
  id v472; // x25
  void *v473; // x22
  __CFString *v474; // x21
  __int64 v475; // x28
  __CFString *v476; // x26
  void *i; // x23
  __CFString *v478; // x20
  __int64 v479; // x0
  unsigned __int8 v480; // w0
  __CFString *v481; // x2
  __CFString *v482; // x0
  __CFString *v483; // x19
  __CFString *v484; // x2
  __int64 v485; // x0
  os_log_s *v486; // x19
  int v487; // w8
  const char *v488; // x3
  __int64 v489; // x0
  int v490; // w8
  NSDictionary *v491; // x19
  __int64 v492; // x0
  os_log_s *v493; // x19
  int v494; // w8
  __int64 v495; // x0
  int v496; // w8
  __int64 v497; // x0
  __int64 v498; // x0
  int v499; // w8
  __int64 v500; // x19
  NSDictionary *v501; // x20
  id v502; // x19
  os_log_s *v503; // x19
  int v504; // w23
  int v505; // w25
  unsigned int v506; // w22
  NSString *v507; // x20
  __CFString *v508; // x8
  unsigned __int8 v509; // w20
  id v510; // x0
  void *v511; // x19
  void *v512; // x22
  os_log_s *v513; // x19
  int v514; // w20
  __int64 v515; // x0
  os_log_s *v516; // x19
  int v517; // w20
  int v518; // w21
  void *v519; // x21
  NSNumber *v520; // x19
  const char *v521; // x1
  NSData *v522; // x19
  NSNumber *v523; // x19
  void *v524; // x19
  id v525; // x20
  _LSDisplayNameConstructor *v526; // x0
  _LSDisplayNameConstructor *v527; // x26
  id v528; // x20
  __int64 v529; // x8
  unsigned int v530; // w1
  __CFString *v531; // x21
  __CFString *v532; // x25
  NSNumber *v533; // x20
  void *v534; // x20
  const void *v535; // x0
  __int64 v536; // x0
  const __CFDictionary *v537; // x20
  __int64 v538; // x0
  __int64 v539; // x21
  const void *v540; // x0
  const void *v541; // x20
  __int64 v542; // x23
  dispatch_queue_s *v543; // x21
  NSString *v544; // x19
  __int64 v545; // x8
  unsigned int v546; // w20
  __LSASN *v547; // x0
  __LSASN *v548; // x19
  os_log_s *v549; // x20
  unsigned int v550; // w21
  unsigned __int64 v551; // x22
  unsigned int v552; // w0
  os_log_s *v553; // x19
  int v554; // w20
  int v555; // w21
  unsigned int v556; // w0
  os_log_s *v557; // x19
  int v558; // w20
  int v559; // w21
  unsigned int v560; // w0
  FSNode *v561; // x1
  __int64 v562; // x0
  os_log_s *v563; // x19
  int v564; // w20
  const char *v565; // x3
  os_log_s *v566; // x1
  os_log_type_t v567; // w2
  int v568; // w20
  int v569; // w20
  NSDictionary *v570; // x19
  NSMutableDictionary *v571; // x20
  NSNumber *v572; // x21
  unsigned int v573; // w20
  id v574; // x0
  void *v575; // x19
  id v576; // x21
  os_log_s *v577; // x22
  int v578; // w23
  int v579; // w25
  __int128 *v580; // x8
  __int64 v581; // x0
  os_log_s *v582; // x22
  int v583; // w23
  int v584; // w25
  __int128 *v585; // x8
  const LSBundleData *v586; // x22
  _LSOpen2Options *v587; // x0
  _LSOpen2Options *v588; // x21
  __CFString *v589; // x25
  __CFString *v590; // x0
  NSString *v591; // x21
  NSString *v592; // x22
  void *v593; // x0
  void *v594; // x26
  void *v595; // x0
  os_log_s *v596; // x25
  int v597; // w23
  os_log_s *v598; // x25
  int v599; // w23
  __int64 v600; // x0
  id v601; // x27
  int v602; // w23
  const char *v603; // x3
  unsigned __int64 v604; // x25
  unsigned __int64 v605; // x0
  os_log_s *v606; // x25
  int v607; // w23
  os_log_s *v608; // x25
  int v609; // w23
  __int64 v610; // x0
  int v611; // w23
  __int64 IsStopped; // x0
  CFTypeID v613; // x25
  pid_t v614; // w25
  int v615; // w23
  __int64 v616; // x22
  int *v617; // x0
  int v618; // w28
  os_log_s *v619; // x26
  os_log_s *v620; // x22
  int v621; // w23
  os_log_s *v622; // x22
  int v623; // w23
  os_log_s *v624; // x22
  int v625; // w23
  __int64 v626; // x22
  __int64 v627; // x0
  NSDictionary *IsConnected; // x0
  int v629; // w26
  bool v630; // w25
  os_log_s *v631; // x27
  int v632; // w23
  const char *v633; // x3
  os_log_s *v634; // x1
  os_log_type_t v635; // w2
  bool v636; // w8
  int v637; // w23
  os_log_s *v638; // x25
  int v639; // w23
  NSArray *v640; // x0
  NSArray *v641; // x19
  os_log_s *v642; // x21
  int v643; // w23
  int v644; // w25
  void *v645; // x22
  void *v646; // x19
  int v647; // w8
  void *v648; // x19
  os_log_s *v649; // x21
  void *v650; // x22
  id v651; // x21
  void *v652; // x22
  _BOOL8 v653; // x0
  os_log_s *v654; // x19
  int v655; // w20
  const char *v656; // x3
  os_log_s *v657; // x19
  int v658; // w20
  __int64 v659; // x0
  os_log_s *v660; // x19
  int v661; // w20
  int v662; // w20
  __int64 v663; // x19
  os_log_s *v665; // x20
  int v666; // w19
  void *v667; // x0
  os_log_s *v668; // x19
  int v669; // w20
  int v670; // w21
  unsigned int v671; // w0
  os_log_s *v672; // x20
  void *v673; // x22
  os_log_s *v674; // x20
  void *v675; // x22
  void *v676; // x0
  os_log_s *v677; // x20
  void *v678; // x22
  NSURL *v679; // x20
  FSNode *v680; // x22
  os_log_s *v681; // x20
  void *v682; // x22
  void *v683; // x0
  void *v684; // x26
  id v685; // x20
  os_log_s *v686; // x20
  void *v687; // x22
  __int64 v688; // x0
  FSNode *v689; // x25
  id v690; // x27
  __int64 v691; // x0
  os_log_s *v692; // x22
  const char *v693; // x3
  int v694; // w19
  __int64 v695; // x0
  os_log_s *v696; // x20
  __int64 v697; // x0
  os_log_s *v698; // x20
  void *v699; // x22
  os_log_s *v700; // x20
  void *v701; // x22
  void *v702; // x0
  __int64 v703; // x0
  os_log_s *v704; // x22
  id v705; // x25
  int v706; // [xsp+28h] [xbp-5B8h]
  id v707; // [xsp+40h] [xbp-5A0h]
  uint64_t v708; // [xsp+50h] [xbp-590h]
  unsigned int v709; // [xsp+58h] [xbp-588h]
  int v710; // [xsp+60h] [xbp-580h]
  int v711; // [xsp+64h] [xbp-57Ch]
  void *v712; // [xsp+68h] [xbp-578h]
  int v713; // [xsp+74h] [xbp-56Ch]
  id v714; // [xsp+78h] [xbp-568h]
  void *v715; // [xsp+88h] [xbp-558h]
  void *v716; // [xsp+90h] [xbp-550h]
  void *v717; // [xsp+98h] [xbp-548h]
  id v718; // [xsp+A0h] [xbp-540h]
  NSMutableArray *v719; // [xsp+A8h] [xbp-538h]
  id v720; // [xsp+B0h] [xbp-530h]
  id v721; // [xsp+B8h] [xbp-528h]
  int v722; // [xsp+CCh] [xbp-514h]
  _LSOpen2Options *v723; // [xsp+D0h] [xbp-510h]
  NSString *v724; // [xsp+D8h] [xbp-508h]
  unsigned int v725; // [xsp+E0h] [xbp-500h]
  void *v726; // [xsp+E0h] [xbp-500h]
  NSNumber *v727; // [xsp+E8h] [xbp-4F8h]
  id v728; // [xsp+E8h] [xbp-4F8h]
  NSError *v729; // [xsp+E8h] [xbp-4F8h]
  NSError *v730; // [xsp+E8h] [xbp-4F8h]
  NSURL *v731; // [xsp+F0h] [xbp-4F0h]
  NSNumber *v732; // [xsp+F0h] [xbp-4F0h]
  unsigned int v733; // [xsp+F0h] [xbp-4F0h]
  id v734; // [xsp+F0h] [xbp-4F0h]
  void *v735; // [xsp+F0h] [xbp-4F0h]
  NSString *v736; // [xsp+F8h] [xbp-4E8h]
  NSError *v737; // [xsp+F8h] [xbp-4E8h]
  NSError *v738; // [xsp+F8h] [xbp-4E8h]
  void *v739; // [xsp+100h] [xbp-4E0h]
  id v740; // [xsp+100h] [xbp-4E0h]
  void *v741; // [xsp+100h] [xbp-4E0h]
  void *v742; // [xsp+100h] [xbp-4E0h]
  __CFString *v743; // [xsp+108h] [xbp-4D8h]
  LSBundleData *v744; // [xsp+108h] [xbp-4D8h]
  id v745; // [xsp+108h] [xbp-4D8h]
  id v746; // [xsp+108h] [xbp-4D8h]
  id v747; // [xsp+110h] [xbp-4D0h]
  NSString *v748; // [xsp+110h] [xbp-4D0h]
  id v750; // [xsp+120h] [xbp-4C0h]
  void *v751; // [xsp+120h] [xbp-4C0h]
  __CFString *v753; // [xsp+130h] [xbp-4B0h]
  NSString *v754; // [xsp+138h] [xbp-4A8h]
  id v755; // [xsp+140h] [xbp-4A0h]
  NSDate *v756; // [xsp+148h] [xbp-498h]
  void *v757; // [xsp+150h] [xbp-490h]
  NSDictionary *v758; // [xsp+150h] [xbp-490h]
  void *v759; // [xsp+150h] [xbp-490h]
  id v760; // [xsp+160h] [xbp-480h]
  id v761; // [xsp+168h] [xbp-478h]
  NSString *v763; // [xsp+178h] [xbp-468h]
  id v764; // [xsp+180h] [xbp-460h]
  _LSOpen2Options *v765; // [xsp+188h] [xbp-458h]
  const void *v766; // [xsp+190h] [xbp-450h]
  void *v768; // [xsp+198h] [xbp-448h]
  id v769; // [xsp+1A0h] [xbp-440h]
  void *v770; // [xsp+1A8h] [xbp-438h]
  void *v771; // [xsp+1B0h] [xbp-430h]
  NSError *v772; // [xsp+1B0h] [xbp-430h]
  NSMutableArray *v773; // [xsp+1B0h] [xbp-430h]
  id v774; // [xsp+1B8h] [xbp-428h]
  unsigned int v775; // [xsp+1B8h] [xbp-428h]
  id v776; // [xsp+1C0h] [xbp-420h] BYREF
  id v777; // [xsp+1C8h] [xbp-418h] BYREF
  id v778; // [xsp+1D0h] [xbp-410h] BYREF
  id v779; // [xsp+1D8h] [xbp-408h] BYREF
  __int128 v780; // [xsp+1E0h] [xbp-400h] BYREF
  __int128 v781; // [xsp+1F0h] [xbp-3F0h]
  __int128 v782; // [xsp+200h] [xbp-3E0h]
  __int128 v783; // [xsp+210h] [xbp-3D0h]
  __int64 v784[5]; // [xsp+228h] [xbp-3B8h] BYREF
  __int64 v785[4]; // [xsp+250h] [xbp-390h] BYREF
  NSString *v786; // [xsp+270h] [xbp-370h]
  __int64 *v787; // [xsp+278h] [xbp-368h]
  __int128 *v788; // [xsp+280h] [xbp-360h]
  __int128 *v789; // [xsp+288h] [xbp-358h]
  NSError *v790; // [xsp+290h] [xbp-350h]
  NSError *v791; // [xsp+298h] [xbp-348h] BYREF
  id v792; // [xsp+2A0h] [xbp-340h] BYREF
  id v793; // [xsp+2A8h] [xbp-338h] BYREF
  unsigned __int8 v794; // [xsp+2B7h] [xbp-329h] BYREF
  __int64 v795; // [xsp+2B8h] [xbp-328h] BYREF
  __int64 *v796; // [xsp+2C0h] [xbp-320h]
  __int64 v797; // [xsp+2C8h] [xbp-318h]
  int v798; // [xsp+2D0h] [xbp-310h]
  __int64 v799; // [xsp+2D8h] [xbp-308h] BYREF
  __int64 *v800; // [xsp+2E0h] [xbp-300h]
  __int64 v801; // [xsp+2E8h] [xbp-2F8h]
  int v802; // [xsp+2F0h] [xbp-2F0h]
  char *v803; // [xsp+2F8h] [xbp-2E8h] BYREF
  char v804; // [xsp+30Fh] [xbp-2D1h]
  int v805; // [xsp+314h] [xbp-2CCh] BYREF
  void *v806; // [xsp+318h] [xbp-2C8h] BYREF
  __CFString *v807; // [xsp+320h] [xbp-2C0h] BYREF
  NSError *v808; // [xsp+328h] [xbp-2B8h] BYREF
  char v809[128]; // [xsp+330h] [xbp-2B0h] BYREF
  __int64 v810[2]; // [xsp+3B0h] [xbp-230h] BYREF
  __int64 v811[2]; // [xsp+3C0h] [xbp-220h] BYREF
  __int64 v812[2]; // [xsp+3D0h] [xbp-210h] BYREF
  const __LSASN *v813[4]; // [xsp+3E0h] [xbp-200h] BYREF
  _BYTE v814[32]; // [xsp+400h] [xbp-1E0h] BYREF
  __int128 v815; // [xsp+420h] [xbp-1C0h] BYREF
  __int128 v816; // [xsp+430h] [xbp-1B0h]
  __int128 v817; // [xsp+440h] [xbp-1A0h] BYREF
  __int128 v818; // [xsp+450h] [xbp-190h]
  __int128 v819; // [xsp+460h] [xbp-180h] BYREF
  __int128 v820; // [xsp+470h] [xbp-170h]
  __int128 v821[2]; // [xsp+480h] [xbp-160h] BYREF
  _BYTE v822[58]; // [xsp+4A0h] [xbp-140h] BYREF
  __int16 v823; // [xsp+4DAh] [xbp-106h]
  __CFString *v824; // [xsp+4DCh] [xbp-104h]
  __int16 v825; // [xsp+4E4h] [xbp-FCh]
  __CFString *v826; // [xsp+4E6h] [xbp-FAh]
  __int16 v827; // [xsp+4EEh] [xbp-F2h]
  __CFString *v828; // [xsp+4F0h] [xbp-F0h]
  __int16 v829; // [xsp+4F8h] [xbp-E8h]
  __CFString *v830; // [xsp+4FAh] [xbp-E6h]
  __int16 v831; // [xsp+502h] [xbp-DEh]
  _LSOpen2Options *v832; // [xsp+504h] [xbp-DCh]
  __int16 v833; // [xsp+50Ch] [xbp-D4h]
  __CFString *v834; // [xsp+50Eh] [xbp-D2h]
  __int128 v835[2]; // [xsp+520h] [xbp-C0h] BYREF
  __int128 v836; // [xsp+540h] [xbp-A0h]
  __int128 v837; // [xsp+550h] [xbp-90h]

  v760 = objc_retain(a2);
  v764 = objc_retain(a8);
  v765 = objc_retain(a12);
  v17 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
  v18 = a10;
  if ( j__os_log_type_enabled_3(v17, OS_LOG_TYPE_INFO) )
  {
    v774 = objc_retain(objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, a10)));
    v771 = objc_retainAutoreleasedReturnValue(objc_msgSend(v760, "URL"));
    if ( a6 )
    {
      appleEventSuiteAndIDasString(a6);
      if ( v804 >= 0 )
        v19 = &v803;
      else
        v19 = v803;
    }
    else
    {
      v19 = "-";
    }
    v757 = a5;
    if ( a5 )
      v20 = objc_retainAutoreleasedReturnValue(objc_msgSend(a5, "componentsJoinedByString:", CFSTR(" ")));
    else
      v20 = CFSTR("-");
    v21 = &stru_1ED1C6B98;
    if ( (a3 & 0x200) != 0 )
      v22 = CFSTR("dontSwitch ");
    else
      v22 = &stru_1ED1C6B98;
    if ( (a3 & 0x10000) != 0 )
      v23 = CFSTR("async ");
    else
      v23 = &stru_1ED1C6B98;
    if ( (a3 & 0x80000) != 0 )
      v24 = CFSTR("newInstance ");
    else
      v24 = &stru_1ED1C6B98;
    if ( (a3 & 0x100000) != 0 )
      v25 = CFSTR("hide ");
    else
      v25 = &stru_1ED1C6B98;
    if ( (a3 & 0x200000) != 0 )
      v26 = CFSTR("hideOthers ");
    else
      v26 = &stru_1ED1C6B98;
    if ( v764 )
      v21 = objc_retainAutoreleasedReturnValue(objc_msgSend(v764, "componentsJoinedByString:", CFSTR(",")));
    *v822 = 138546179;
    *&v822[4] = v774;
    *&v822[12] = 2113;
    *&v822[14] = v771;
    *&v822[22] = 2082;
    *&v822[24] = v19;
    *&v822[32] = 2114;
    *&v822[34] = v20;
    *&v822[42] = 1024;
    *&v822[44] = a3;
    *&v822[48] = 2112;
    *&v822[50] = v22;
    v823 = 2112;
    v824 = v23;
    v825 = 2112;
    v826 = v24;
    v827 = 2112;
    v828 = v25;
    v829 = 2112;
    v830 = v26;
    v831 = 2114;
    v832 = v765;
    v833 = 2114;
    v834 = v21;
    j___os_log_impl_1(
      &dword_180981000,
      v17,
      OS_LOG_TYPE_INFO,
      "_LSLaunchRB(%{public}@ %{private}@, event=%{public}s, args=%{public}@ 0x%x/%@%@%@%@%@ opts=%{public}@ %{public}@",
      v822,
      0x76u);
    if ( v764 )
      objc_release(v21);
    a5 = v757;
    v18 = a10;
    if ( v757 )
      objc_release(v20);
    if ( a6 && v804 < 0 )
      operator delete(v803);
    objc_release(v771);
    objc_release(v774);
    objc_release(v774);
  }
  objc_release(v17);
  v799 = 0LL;
  v800 = &v799;
  v801 = 0x2020000000LL;
  v802 = 0;
  v795 = 0LL;
  v796 = &v795;
  v797 = 0x2020000000LL;
  v798 = v18;
  v794 = 0;
  v755 = objc_retain(v760);
  v756 = objc_retainAutoreleasedReturnValue(+[NSDate date](&OBJC_CLASS___NSDate, "date"));
  if ( a14 )
    *a14 = 0LL;
  if ( (((a3 >> 14) & 0x200 | a3) & 0x80000000) == 0 )
    v27 = (a3 >> 14) & 0x200 | a3;
  else
    v27 = a3 | 0x200;
  v28 = objc_retain(v755);
  v775 = v27;
  v770 = v28;
  if ( (v27 & 0x20000000) != 0 )
  {
    v31 = *(v796 + 6);
    v32 = objc_retainAutoreleasedReturnValue(objc_msgSend(v28, "pathWithError:", 0LL));
    if ( v32 )
    {
      v33 = _LSBundleGet(a1->db, v31);
      v34 = objc_retainAutoreleasedReturnValue(constructExecutablePathFromBundleData(a1, v31, v33, v32, 0));
      if ( v34 )
      {
        v35 = objc_retainAutorelease(v32);
        v36 = j__realpath_DARWIN_EXTSN_2(-[NSString fileSystemRepresentation](v35, "fileSystemRepresentation"), 0LL);
        v37 = objc_retainAutorelease(v34);
        v38 = j__realpath_DARWIN_EXTSN_2(objc_msgSend(v37, "fileSystemRepresentation"), 0LL);
        v39 = v38;
        v40 = 1;
        if ( v36 && v38 )
        {
          v41 = j__strlen_10(v36);
          v40 = j__strncmp_4(v39, v36, v41) == 0;
        }
        j__free_12(v36);
        j__free_12(v39);
        objc_release(v37);
        objc_release(v35);
        if ( v40 )
          v30 = 0;
        else
          v30 = -10827;
        goto LABEL_52;
      }
      objc_release(v32);
    }
    v30 = 0;
LABEL_52:
    v29 = v800;
    *(v800 + 6) = v30;
    goto LABEL_53;
  }
  v29 = v800;
  v30 = *(v800 + 6);
LABEL_53:
  if ( (v775 & 0x40000) != 0 && !v30 )
  {
    *(v29 + 24) = -10828;
    v42 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
    if ( j__os_log_type_enabled_3(v42, OS_LOG_TYPE_ERROR) )
    {
      v43 = objc_retainAutoreleasedReturnValue(objc_msgSend(v770, "URL"));
      v44 = *(v800 + 6);
      *v822 = 138478083;
      *&v822[4] = v43;
      *&v822[12] = 1024;
      *&v822[14] = v44;
      j___os_log_impl_1(
        &dword_180981000,
        v42,
        OS_LOG_TYPE_ERROR,
        "LAUNCH:kLSLaunchInClassic is not supported, node=%{private}@ status=%d",
        v822,
        0x12u);
      objc_release(v43);
    }
    objc_release(v42);
    v30 = *(v800 + 6);
  }
  if ( v30 )
  {
    v772 = 0LL;
  }
  else
  {
    v45 = objc_retain(v770);
    *&v835[0] = 0LL;
    v46 = objc_msgSend(v45, "getWriterBundleIdentifier:error:", v835, 0LL);
    v47 = v46 & (*&v835[0] != 0LL);
    if ( v47 == 1 )
    {
      *&v819 = CFSTR("LSUpdaterBundleID");
      *&v821[0] = *&v835[0];
      v48 = objc_retainAutoreleasedReturnValue(
              +[NSDictionary dictionaryWithObjects:forKeys:count:](
                &OBJC_CLASS___NSDictionary,
                "dictionaryWithObjects:forKeys:count:",
                v821,
                &v819,
                1LL));
      v49 = objc_autorelease(objc_retainAutoreleasedReturnValue(_LSMakeNSErrorImpl(
                                                                  CFSTR("NSOSStatusErrorDomain"),
                                                                  -10699LL,
                                                                  "isAppStoreInTheProcesSOfUpdatingApplication",
                                                                  552LL,
                                                                  v48)));
      objc_release(v48);
      if ( *&v835[0] && !objc_msgSend(*&v835[0], "caseInsensitiveCompare:", CFSTR("com.apple.storeagent")) )
      {
        v50 = objc_retainAutoreleasedReturnValue(j__dispatch_get_global_queue_2(0LL, 0LL));
        *v822 = &OBJC_CLASS_____NSStackBlock__;
        *&v822[8] = 3254779904LL;
        *&v822[16] = ___ZL43isAppStoreInTheProcesSOfUpdatingApplicationP9LSContextjP6FSNodePU15__autoreleasingP7NSError_block_invoke;
        *&v822[24] = &__block_descriptor_40_ea8_32s_e5_v8__0l;
        *&v822[32] = objc_retain(v45);
        j__dispatch_async_3(v50, v822);
        objc_release(v50);
        objc_release(*&v822[32]);
      }
    }
    else
    {
      v49 = 0LL;
    }
    objc_release(*&v835[0]);
    objc_release(v45);
    v772 = objc_retain(v49);
    if ( v47 )
    {
      *(v800 + 6) = -10699;
      v51 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
      if ( j__os_log_type_enabled_3(v51, OS_LOG_TYPE_ERROR) )
      {
        v52 = objc_retain(objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, *(v796 + 6))));
        v53 = *(v800 + 6);
        *v822 = 138544131;
        *&v822[4] = v52;
        *&v822[12] = 2113;
        *&v822[14] = v45;
        *&v822[22] = 1024;
        *&v822[24] = v53;
        *&v822[28] = 2114;
        *&v822[30] = v772;
        j___os_log_impl_1(
          &dword_180981000,
          v51,
          OS_LOG_TYPE_ERROR,
          "LAUNCH:Refusing to launch application because it is being updated by the AppStore, %{public}@ node=%{private}@"
          " status=%d error=%{public}@",
          v822,
          0x26u);
        objc_release(v52);
        objc_release(v52);
      }
      objc_release(v51);
      if ( a14 )
      {
        v772 = objc_retainAutorelease(v772);
        *a14 = v772;
      }
    }
  }
  if ( !*(v800 + 6) && objc_msgSend(v770, "isInTrash") )
  {
    *(v800 + 6) = -10660;
    v54 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
    if ( j__os_log_type_enabled_3(v54, OS_LOG_TYPE_ERROR) )
    {
      v55 = objc_retain(objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, *(v796 + 6))));
      v56 = objc_retainAutoreleasedReturnValue(objc_msgSend(v770, "URL"));
      v57 = *(v800 + 6);
      *v822 = 138543875;
      *&v822[4] = v55;
      *&v822[12] = 2113;
      *&v822[14] = v56;
      *&v822[22] = 1024;
      *&v822[24] = v57;
      j___os_log_impl_1(
        &dword_180981000,
        v54,
        OS_LOG_TYPE_ERROR,
        "LAUNCH:Refusing to launch application .inTrash = YES, %{public}@ node=%{private}@ status=%d",
        v822,
        0x1Cu);
      objc_release(v56);
      objc_release(v55);
      objc_release(v55);
    }
    objc_release(v54);
  }
  if ( *(v800 + 6) )
  {
    v761 = 0LL;
    v769 = v770;
    goto LABEL_173;
  }
  v58 = *(v796 + 6);
  v59 = objc_retain(v770);
  v60 = objc_retain(v764);
  if ( !a1 )
  {
    v61 = 0;
    goto LABEL_147;
  }
  v61 = 0;
  if ( v58 && a1->db )
  {
    v62 = _LSBundleGet(a1->db, v58);
    v63 = v62;
    if ( !v62 )
    {
      v64 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
      if ( !j__os_log_type_enabled_3(v64, OS_LOG_TYPE_ERROR) )
      {
        v61 = -10814;
LABEL_146:
        objc_release(v64);
        goto LABEL_147;
      }
      v82 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
      *v822 = 138478083;
      *&v822[4] = v82;
      *&v822[12] = 1024;
      v61 = -10814;
      *&v822[14] = -10814;
      j___os_log_impl_1(
        &dword_180981000,
        v64,
        OS_LOG_TYPE_ERROR,
        "LAUNCH:Unable to launch application because it there was no bundleData for node=%{private}@ status=%d",
        v822,
        0x12u);
      v83 = v82;
LABEL_145:
      objc_release(v83);
      goto LABEL_146;
    }
    v64 = _CSStringCopyCFString(a1->db->store, *(v62 + 12));
    if ( !_LSBundleMeetsMinimumVersionRequirement(a1->db, v58, v63) )
    {
      v84 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
      if ( j__os_log_type_enabled_3(v84, OS_LOG_TYPE_ERROR) )
      {
        v85 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
        *v822 = 138543875;
        *&v822[4] = v64;
        *&v822[12] = 2113;
        *&v822[14] = v85;
        *&v822[22] = 1026;
        *&v822[24] = -10664;
        j___os_log_impl_1(
          &dword_180981000,
          v84,
          OS_LOG_TYPE_ERROR,
          "LAUNCH: Application being launched requires a later version of the operating system to execute, %{public}@ nod"
          "e=%{private}@ status=%{public}d",
          v822,
          0x1Cu);
        objc_release(v85);
      }
      objc_release(v84);
      v61 = -10664;
      goto LABEL_146;
    }
    if ( (*(v63 + 149) & 0x10) != 0 )
      goto LABEL_88;
    v65 = *(v63 + 224);
    v821[0] = *(v63 + 208);
    v821[1] = v65;
    v66 = *(v63 + 256);
    v819 = *(v63 + 240);
    v820 = v66;
    if ( _LSBundleDataMinSystemVersionAllowsCurrentSystem(v63) )
    {
      *v822 = v819;
      *&v822[16] = v820;
      memset(v835, 0, sizeof(v835));
      if ( !_LSVersionNumberCompare(v822, v835)
        || (v817 = v819,
            v818 = v820,
            v67 = *(v63 + 256),
            v815 = *(v63 + 240),
            v816 = v67,
            _LSVersionNumberCompare(&v817, &v815) != -1) )
      {
        v68 = *(v63 + 292);
        *v814 = *(v63 + 276);
        *&v814[16] = v68;
        v69 = *(v63 + 292);
        *v822 = *(v63 + 276);
        *&v822[16] = v69;
        memset(v835, 0, sizeof(v835));
        if ( _LSVersionNumberCompare(v822, v835) && !_LSBundleDataExecMinOSVersionAllowsCurrentSystem(v63) )
        {
          v101 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
          if ( j__os_log_type_enabled_3(v101, OS_LOG_TYPE_ERROR) )
          {
            v835[0] = *v814;
            v835[1] = *&v814[16];
            v102 = objc_retain(objc_retainAutoreleasedReturnValue(_LSVersionNumberGetStringRepresentation(v835)));
            _LSGetCurrentSystemVersion(v813);
            v103 = objc_retainAutoreleasedReturnValue(_LSVersionNumberGetStringRepresentation(v813));
            v104 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
            *v822 = 138544387;
            *&v822[4] = v102;
            *&v822[12] = 2114;
            *&v822[14] = v103;
            *&v822[22] = 2114;
            *&v822[24] = v64;
            *&v822[32] = 2113;
            *&v822[34] = v104;
            *&v822[42] = 1026;
            *&v822[44] = -10825;
            j___os_log_impl_1(
              &dword_180981000,
              v101,
              OS_LOG_TYPE_ERROR,
              "LAUNCH: Application being launched requires conditional %{public}@, but is being run on an earlier version"
              " of the operating system %{public}@ to execute, is on %{public}@ node=%{private}@ status=%{public}d",
              v822,
              0x30u);
            objc_release(v104);
            objc_release(v102);
            objc_release(v103);
            objc_release(v102);
          }
          v105 = v101;
LABEL_984:
          objc_release(v105);
          v61 = -10825;
          goto LABEL_146;
        }
        if ( !*(v63 + 524) && !j__getenv_8("__FORCE_MANAGED_USER") )
          goto LABEL_1052;
LABEL_88:
        if ( canThisProcessLaunchManagedApplications(void)::sOnce != -1 )
          j__dispatch_once_3(&canThisProcessLaunchManagedApplications(void)::sOnce, &__block_literal_global_174);
        if ( !canThisProcessLaunchManagedApplications(void)::sResult )
          goto LABEL_123;
        v70 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
        if ( j__os_log_type_enabled_3(v70, OS_LOG_TYPE_DEBUG) )
        {
          *v822 = 0;
          j___os_log_impl_1(
            &dword_180981000,
            v70,
            OS_LOG_TYPE_DEBUG,
            "LAUNCH: This process can directly launch managed applications.",
            v822,
            2u);
        }
        objc_release(v70);
        if ( !canThisProcessLaunchManagedApplications(void)::sResult )
        {
LABEL_123:
          v86 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
          if ( !j__os_log_type_enabled_3(v86, OS_LOG_TYPE_INFO) )
          {
LABEL_133:
            objc_release(v86);
            v61 = -10668;
            goto LABEL_146;
          }
          *v822 = 0;
          v87 = "LAUNCH: Application being launched has managed personas, so returning kLSLaunchNeedsToGoThruHelperErr to"
                " force it to launch tru CSUI.";
        }
        else
        {
LABEL_1052:
          if ( *(v63 + 20) != 2 )
            goto LABEL_103;
          if ( canThisProcessLaunchContainerizedApplications(void)::sOnce != -1 )
            j__dispatch_once_3(&canThisProcessLaunchContainerizedApplications(void)::sOnce, &__block_literal_global_179);
          if ( canThisProcessLaunchContainerizedApplications(void)::sResult )
          {
            v71 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
            if ( j__os_log_type_enabled_3(v71, OS_LOG_TYPE_DEBUG) )
            {
              *v822 = 0;
              j___os_log_impl_1(
                &dword_180981000,
                v71,
                OS_LOG_TYPE_DEBUG,
                "LAUNCH: This process can directly launch ios apps.",
                v822,
                2u);
            }
            objc_release(v71);
            if ( canThisProcessLaunchContainerizedApplications(void)::sResult )
            {
LABEL_103:
              if ( (*(v63 + 161) & 1) != 0 )
              {
                v96 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
                if ( j__os_log_type_enabled_3(v96, OS_LOG_TYPE_ERROR) )
                {
                  v97 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
                  *v822 = 138543875;
                  *&v822[4] = v64;
                  *&v822[12] = 2113;
                  *&v822[14] = v97;
                  *&v822[22] = 1024;
                  *&v822[24] = -10828;
                  j___os_log_impl_1(
                    &dword_180981000,
                    v96,
                    OS_LOG_TYPE_ERROR,
                    "LAUNCH:Unable to launch kLSItemInfoIsClassicApp for %{public}@ node=%{private}@ status=%d",
                    v822,
                    0x1Cu);
                  objc_release(v97);
                }
                objc_release(v96);
                v61 = -10828;
                goto LABEL_146;
              }
              v72 = *(v63 + 148);
              if ( (v72 & 0x800000000LL) != 0 )
              {
                v98 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
                if ( !j__os_log_type_enabled_3(v98, OS_LOG_TYPE_ERROR) )
                {
LABEL_701:
                  objc_release(v98);
                  v61 = -10657;
                  goto LABEL_146;
                }
                v99 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
                *v822 = 138543875;
                *&v822[4] = v64;
                *&v822[12] = 2113;
                *&v822[14] = v99;
                *&v822[22] = 1024;
                *&v822[24] = 0;
                v100 = "LAUNCH:Unable to launch application in snapshots directory, %{public}@ node=%{private}@ status=%d";
              }
              else
              {
                if ( (v72 & 0x1000000000LL) == 0 )
                {
                  if ( (isApplicationRequiredVersionAcceptable(v63) & 1) != 0 )
                  {
                    if ( (*(v63 + 158) & 0x80) == 0 )
                    {
                      if ( !*(v63 + 192) )
                      {
                        v681 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
                        if ( j__os_log_type_enabled_3(v681, OS_LOG_TYPE_ERROR) )
                        {
                          v682 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
                          *v822 = 138543875;
                          *&v822[4] = v64;
                          *&v822[12] = 2113;
                          *&v822[14] = v682;
                          *&v822[22] = 1024;
                          *&v822[24] = -10827;
                          j___os_log_impl_1(
                            &dword_180981000,
                            v681,
                            OS_LOG_TYPE_ERROR,
                            "LAUNCH:Returning kLSNoExecutableErr because bundle has no inode, %{public}@ node=%{private}@ status=%d",
                            v822,
                            0x1Cu);
                          objc_release(v682);
                        }
                        objc_release(v681);
                        v61 = -10827;
                        goto LABEL_146;
                      }
                      if ( v60 )
                      {
                        v73 = objc_retain(v60);
                        v74 = -[LSSliceInfo initWithType:subtype:](
                                objc_alloc(&OBJC_CLASS___LSSliceInfo),
                                "initWithType:subtype:",
                                0xFFFFFFFFLL,
                                0xFFFFFFFFLL);
                        v75 = objc_msgSend(v73, "containsObject:", v74);
                        objc_release(v74);
                        if ( (v75 & 1) != 0 || (*(v63 + 148) & 0x10) != 0 )
                        {
                          objc_release(v73);
                        }
                        else
                        {
                          v76 = objc_retain(v73);
                          v77 = objc_alloc_init(&OBJC_CLASS___NSMutableSet);
                          *v822 = &OBJC_CLASS_____NSStackBlock__;
                          *&v822[8] = 3254779904LL;
                          *&v822[16] = ___ZL41filterRequestedArchitecturesForBundleDataPK12LSBundleDataP7NSArrayIP11LSSliceInfoE_block_invoke;
                          *&v822[24] = &__block_descriptor_56_ea8_32s40s_e26_v24__0_LSSliceData_ii_8_16l;
                          *&v822[48] = v63;
                          v78 = objc_retain(v76);
                          *&v822[32] = v78;
                          v79 = objc_retain(v77);
                          *&v822[40] = v79;
                          _LSEnumerateSliceMask(*(v63 + 140), v822);
                          v80 = objc_retainAutoreleasedReturnValue(-[NSSet allObjects](v79, "allObjects"));
                          objc_release(*&v822[40]);
                          objc_release(*&v822[32]);
                          objc_release(v79);
                          objc_release(v78);
                          v81 = -[NSArray count](v80, "count");
                          objc_release(v80);
                          objc_release(v78);
                          if ( !v81 )
                          {
                            if ( requestedArchitectureWouldBeSupportedIfCambriaWereInstalled(v63, v78) )
                              v61 = -10669;
                            else
                              v61 = -10661;
                            goto LABEL_146;
                          }
                        }
                      }
                    }
                    if ( (*(v63 + 149) & 0x20) != 0 )
                    {
                      v688 = _LSLoadJavaLaunchingFramework();
                      if ( !_LSIsJavaInstalled(v688) )
                      {
                        v697 = _LSRequestRuntimeInstall(v59);
                        v698 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v697));
                        if ( j__os_log_type_enabled_3(v698, OS_LOG_TYPE_ERROR) )
                        {
                          v699 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
                          *v822 = 138543875;
                          *&v822[4] = v64;
                          *&v822[12] = 2113;
                          *&v822[14] = v699;
                          *&v822[22] = 1024;
                          *&v822[24] = -10658;
                          j___os_log_impl_1(
                            &dword_180981000,
                            v698,
                            OS_LOG_TYPE_ERROR,
                            "LAUNCH:Application requires Java, which is not installed, so failing, %{public}@ node=%{priv"
                            "ate}@, status=%d",
                            v822,
                            0x1Cu);
                          objc_release(v699);
                        }
                        objc_release(v698);
                        v61 = -10658;
                        goto LABEL_146;
                      }
                    }
                    v689 = objc_retain(v59);
                    v690 = objc_retain(v64);
                    if ( !_LSBundleDataGetUnsupportedFormatFlag(a1->db, v63) )
                    {
                      if ( (_LSGetCPUType() & 0xFFFFFF) == 12
                        && (_LS_oah_is_translation_available() & 1) == 0
                        && (*(v63 + 173) & 0x10) == 0 )
                      {
                        *&v821[0] = 0LL;
                        *(&v821[0] + 1) = v821;
                        *&v821[1] = 0x2020000000LL;
                        BYTE8(v821[1]) = 0;
                        *&v819 = 0LL;
                        *(&v819 + 1) = &v819;
                        *&v820 = 0x2020000000LL;
                        BYTE8(v820) = 0;
                        *&v835[0] = &OBJC_CLASS_____NSStackBlock__;
                        *(&v835[0] + 1) = 3254779904LL;
                        *&v835[1] = ___ZL49applicationWouldBeSupportedIfCambriaWereInstalledPK12LSBundleData_block_invoke;
                        *(&v835[1] + 1) = &__block_descriptor_48_ea8_32r40r_e26_v24__0_LSSliceData_ii_8_16l;
                        *&v836 = v821;
                        *(&v836 + 1) = &v819;
                        _LSEnumerateSliceMask(*(v63 + 140), v835);
                        if ( *(*(&v819 + 1) + 24LL) )
                        {
                          v694 = *(*(&v821[0] + 1) + 24LL);
                          j___Block_object_dispose_6(&v819, 8);
                          j___Block_object_dispose_6(v821, 8);
                          if ( !v694 )
                          {
                            v696 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v695));
                            if ( j__os_log_type_enabled_3(v696, OS_LOG_TYPE_INFO) )
                            {
                              LODWORD(v835[0]) = 138543875;
                              *(v835 + 4) = v690;
                              WORD6(v835[0]) = 2113;
                              *(v835 + 14) = v689;
                              WORD3(v835[1]) = 1026;
                              DWORD2(v835[1]) = -10669;
                              j___os_log_impl_1(
                                &dword_180981000,
                                v696,
                                OS_LOG_TYPE_INFO,
                                "LAUNCH: Application cannot be launched because Rosetta is not installed. %{public}@ node"
                                "=%{private}@ status=%{public}d",
                                v835,
                                0x1Cu);
                            }
                            objc_release(v696);
                            v61 = -10669;
                            goto LABEL_1042;
                          }
                        }
                        else
                        {
                          j___Block_object_dispose_6(&v819, 8);
                          j___Block_object_dispose_6(v821, 8);
                        }
                      }
                      objc_release(v690);
                      objc_release(v689);
                      v703 = preflightLaunchWithSystemPolicy(v63, v689);
                      v61 = v703;
                      if ( !v703 )
                      {
LABEL_1049:
                        v64 = v690;
                        goto LABEL_146;
                      }
                      v704 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v703));
                      if ( j__os_log_type_enabled_3(v704, OS_LOG_TYPE_ERROR) )
                      {
                        v705 = objc_retainAutoreleasedReturnValue(-[FSNode URL](v689, "URL"));
                        *v822 = 138543875;
                        *&v822[4] = v690;
                        *&v822[12] = 2113;
                        *&v822[14] = v705;
                        *&v822[22] = 1024;
                        *&v822[24] = v61;
                        j___os_log_impl_1(
                          &dword_180981000,
                          v704,
                          OS_LOG_TYPE_ERROR,
                          "LAUNCH: failed launch-imminent GateKeeper preflight %{public}@ node=%{private}@, status=%d",
                          v822,
                          0x1Cu);
                        objc_release(v705);
                      }
                      v702 = v704;
LABEL_1048:
                      objc_release(v702);
                      goto LABEL_1049;
                    }
                    *&v835[0] = 0LL;
                    *(&v835[0] + 1) = v835;
                    *&v835[1] = 0x2020000000LL;
                    BYTE8(v835[1]) = 0;
                    *&v821[0] = 0LL;
                    *(&v821[0] + 1) = v821;
                    *&v821[1] = 0x2020000000LL;
                    BYTE8(v821[1]) = 1;
                    *&v819 = 0LL;
                    *(&v819 + 1) = &v819;
                    *&v820 = 0x2020000000LL;
                    BYTE8(v820) = 0;
                    *v822 = &OBJC_CLASS_____NSStackBlock__;
                    *&v822[8] = 3254779904LL;
                    *&v822[16] = ___ZL28ensureApplicationIsSupportedP9LSContextPK12LSBundleDataP6FSNodeP8NSString_block_invoke;
                    *&v822[24] = &__block_descriptor_56_ea8_32r40r48r_e26_v24__0_LSSliceData_ii_8_16l;
                    *&v822[32] = v835;
                    *&v822[40] = v821;
                    *&v822[48] = &v819;
                    v691 = _LSEnumerateSliceMask(*(v63 + 140), v822);
                    if ( *(v63 + 132) == 9 )
                    {
                      v692 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v691));
                      v61 = -10667;
                      if ( j__os_log_type_enabled_3(v692, OS_LOG_TYPE_ERROR) )
                      {
                        *v814 = 138543875;
                        *&v814[4] = v690;
                        *&v814[12] = 2113;
                        *&v814[14] = v689;
                        *&v814[22] = 1024;
                        *&v814[24] = -10667;
                        v693 = "LAUNCH:Application in a ROSP-controlled folder should not be launched, %{public}@ node=%{"
                               "private}@ status=%d";
LABEL_1040:
                        j___os_log_impl_1(&dword_180981000, v692, OS_LOG_TYPE_ERROR, v693, v814, 0x1Cu);
                      }
                    }
                    else if ( *(*(&v835[0] + 1) + 24LL) && *(*(&v821[0] + 1) + 24LL) )
                    {
                      v692 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v691));
                      v61 = -10665;
                      if ( j__os_log_type_enabled_3(v692, OS_LOG_TYPE_ERROR) )
                      {
                        *v814 = 138543875;
                        *&v814[4] = v690;
                        *&v814[12] = 2113;
                        *&v814[14] = v689;
                        *&v814[22] = 1024;
                        *&v814[24] = -10665;
                        v693 = "LAUNCH:Application requires PowerPC Rosetta and cannot be launched, %{public}@ node=%{pri"
                               "vate}@ status=%d";
                        goto LABEL_1040;
                      }
                    }
                    else if ( (*(v63 + 142) & 2) != 0 )
                    {
                      v692 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v691));
                      v61 = -10666;
                      if ( j__os_log_type_enabled_3(v692, OS_LOG_TYPE_ERROR) )
                      {
                        *v814 = 138543875;
                        *&v814[4] = v690;
                        *&v814[12] = 2113;
                        *&v814[14] = v689;
                        *&v814[22] = 1024;
                        *&v814[24] = -10666;
                        v693 = "LAUNCH:Application requires garbage collection and cannot be launched, %{public}@ node=%{"
                               "private}@ status=%d";
                        goto LABEL_1040;
                      }
                    }
                    else if ( *(*(&v819 + 1) + 24LL) )
                    {
                      v692 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v691));
                      v61 = -10386;
                      if ( j__os_log_type_enabled_3(v692, OS_LOG_TYPE_ERROR) )
                      {
                        *v814 = 138543875;
                        *&v814[4] = v690;
                        *&v814[12] = 2113;
                        *&v814[14] = v689;
                        *&v814[22] = 1024;
                        *&v814[24] = -10386;
                        v693 = "LAUNCH:Application requires i386 and cannot be launched, %{public}@ node=%{private}@ status=%d";
                        goto LABEL_1040;
                      }
                    }
                    else
                    {
                      v692 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v691));
                      v61 = -10661;
                      if ( j__os_log_type_enabled_3(v692, OS_LOG_TYPE_ERROR) )
                      {
                        *v814 = 138543875;
                        *&v814[4] = v690;
                        *&v814[12] = 2113;
                        *&v814[14] = v689;
                        *&v814[22] = 1024;
                        *&v814[24] = -10661;
                        v693 = "LAUNCH:Application cannot be launched because its unsupported bit is set, %{public}@ node"
                               "=%{private}@ status=%d";
                        goto LABEL_1040;
                      }
                    }
                    objc_release(v692);
                    j___Block_object_dispose_6(&v819, 8);
                    j___Block_object_dispose_6(v821, 8);
                    j___Block_object_dispose_6(v835, 8);
LABEL_1042:
                    objc_release(v690);
                    v702 = v689;
                    goto LABEL_1048;
                  }
                  v672 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
                  if ( j__os_log_type_enabled_3(v672, OS_LOG_TYPE_ERROR) )
                  {
                    v673 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
                    *v822 = 138543875;
                    *&v822[4] = v64;
                    *&v822[12] = 2113;
                    *&v822[14] = v673;
                    *&v822[22] = 1024;
                    *&v822[24] = -10825;
                    j___os_log_impl_1(
                      &dword_180981000,
                      v672,
                      OS_LOG_TYPE_ERROR,
                      "LAUNCH:Returning kLSIncompatibleSystemVersionErr because system version is too old, %{public}@ nod"
                      "e=%{private}@ status=%d",
                      v822,
                      0x1Cu);
                    objc_release(v673);
                  }
                  v105 = v672;
                  goto LABEL_984;
                }
                v98 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
                if ( !j__os_log_type_enabled_3(v98, OS_LOG_TYPE_ERROR) )
                  goto LABEL_701;
                v99 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
                *v822 = 138543875;
                *&v822[4] = v64;
                *&v822[12] = 2113;
                *&v822[14] = v99;
                *&v822[22] = 1024;
                *&v822[24] = 0;
                v100 = "LAUNCH:Unable to launch application in generational storage, %{public}@ node=%{private}@ status=%d";
              }
              j___os_log_impl_1(&dword_180981000, v98, OS_LOG_TYPE_ERROR, v100, v822, 0x1Cu);
              objc_release(v99);
              goto LABEL_701;
            }
          }
          v86 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
          if ( !j__os_log_type_enabled_3(v86, OS_LOG_TYPE_INFO) )
            goto LABEL_133;
          *v822 = 0;
          v87 = "LAUNCH: Application being launched is PLATFORM_IOS, so returning kLSLaunchNeedsToGoThruHelperErr to forc"
                "e it to launch tru CSUI.";
        }
        j___os_log_impl_1(&dword_180981000, v86, OS_LOG_TYPE_INFO, v87, v822, 2u);
        goto LABEL_133;
      }
      v89 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
      if ( !j__os_log_type_enabled_3(v89, OS_LOG_TYPE_ERROR) )
      {
        v61 = -10664;
        goto LABEL_144;
      }
      v835[0] = v819;
      v835[1] = v820;
      v90 = objc_retain(objc_retainAutoreleasedReturnValue(_LSVersionNumberGetStringRepresentation(v835)));
      _LSGetCurrentSystemVersion(v814);
      v91 = objc_retainAutoreleasedReturnValue(_LSVersionNumberGetStringRepresentation(v814));
      v92 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
      *v822 = 138544387;
      *&v822[4] = v90;
      *&v822[12] = 2114;
      *&v822[14] = v91;
      *&v822[22] = 2114;
      *&v822[24] = v64;
      *&v822[32] = 2113;
      *&v822[34] = v92;
      *&v822[42] = 1026;
      v61 = -10664;
      *&v822[44] = -10664;
      v93 = "LAUNCH: Application being launched requires a later version of the operating system, %{public}@, to execute,"
            " is on %{public}@, %{public}@ node=%{private}@ status=%{public}d";
      v94 = v89;
      v95 = 48;
    }
    else
    {
      v88 = *(v63 + 204);
      v89 = objc_retainAutoreleasedReturnValue((_LSOpenLog)());
      if ( !j__os_log_type_enabled_3(v89, OS_LOG_TYPE_ERROR) )
      {
        v61 = -10825;
LABEL_144:
        v83 = v89;
        goto LABEL_145;
      }
      v835[0] = v821[0];
      v835[1] = v821[1];
      v90 = objc_retain(objc_retainAutoreleasedReturnValue(_LSVersionNumberGetStringRepresentation(v835)));
      _LSGetCurrentSystemVersion(&v817);
      v91 = objc_retainAutoreleasedReturnValue(_LSVersionNumberGetStringRepresentation(&v817));
      v92 = objc_retainAutoreleasedReturnValue(objc_msgSend(v59, "URL"));
      *v822 = 138544643;
      *&v822[4] = v90;
      *&v822[12] = 1026;
      *&v822[14] = v88;
      *&v822[18] = 2114;
      *&v822[20] = v91;
      *&v822[28] = 2114;
      *&v822[30] = v64;
      *&v822[38] = 2113;
      *&v822[40] = v92;
      *&v822[48] = 1026;
      v61 = -10825;
      *&v822[50] = -10825;
      v93 = "LAUNCH: Application being launched requires %{public}@ on platform %{public}d, but is being run on an earlie"
            "r version of the operating system %{public}@ to execute, is on %{public}@ node=%{private}@ status=%{public}d";
      v94 = v89;
      v95 = 54;
    }
    j___os_log_impl_1(&dword_180981000, v94, OS_LOG_TYPE_ERROR, v93, v822, v95);
    objc_release(v92);
    objc_release(v90);
    objc_release(v91);
    objc_release(v90);
    goto LABEL_144;
  }
LABEL_147:
  objc_release(v60);
  objc_release(v59);
  *(v800 + 6) = v61;
  if ( v61 )
  {
    v761 = 0LL;
    v769 = v59;
    goto LABEL_173;
  }
  v106 = *(v796 + 6);
  v793 = v59;
  v792 = 0LL;
  v107 = objc_retain(v59);
  v794 = 0;
  *&v835[0] = 0LL;
  v108 = _LSGetTranslocatedAppNodeAndSecureDirectory(a1, v106, v107, &v793, &v792, 0LL, &v794, v835);
  v109 = objc_retainAutorelease(objc_retain(*&v835[0]));
  v110 = v109;
  if ( (v108 & 1) != 0 )
  {
    v111 = 0;
  }
  else
  {
    v112 = _LSGetOSStatusFromNSError(v109);
    v111 = v112;
    v113 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v112));
    if ( j__os_log_type_enabled_3(v113, OS_LOG_TYPE_ERROR) )
    {
      v114 = objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, v106));
      v115 = objc_retainAutoreleasedReturnValue(objc_msgSend(v107, "URL"));
      *v822 = 138543619;
      *&v822[4] = v114;
      *&v822[12] = 2113;
      *&v822[14] = v115;
      j___os_log_impl_1(
        &dword_180981000,
        v113,
        OS_LOG_TYPE_ERROR,
        "LAUNCH: Failure %{public}@ %{private}@ could not be translocated.",
        v822,
        0x16u);
      objc_release(v115);
      objc_release(v114);
    }
    objc_release(v113);
  }
  objc_release(v110);
  objc_release(v107);
  v769 = objc_retain(v793);
  objc_release(v107);
  v761 = objc_retain(v792);
  v116 = objc_retain(v110);
  objc_release(v772);
  *(v800 + 6) = v111;
  if ( !v111 )
  {
    if ( v794 )
    {
      v121 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v117));
      if ( j__os_log_type_enabled_3(v121, OS_LOG_TYPE_INFO) )
      {
        v122 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
        v123 = objc_retainAutoreleasedReturnValue(objc_msgSend(v107, "URL"));
        *v822 = 138478083;
        *&v822[4] = v122;
        *&v822[12] = 2113;
        *&v822[14] = v123;
        j___os_log_impl_1(
          &dword_180981000,
          v121,
          OS_LOG_TYPE_INFO,
          "LAUNCH: translocate to %{private}@ from %{private}@",
          v822,
          0x16u);
        objc_release(v123);
        objc_release(v122);
      }
      objc_release(v121);
    }
    _LSTranslocateCoreAnalyticsAppLaunch(v107);
    v124 = *(v796 + 6);
    v125 = objc_retain(v769);
    v126 = _LSBundleGet(a1->db, v124);
    if ( v126 && *(v126 + 20) == 2 )
    {
      v127 = _LSFindOrRegisterBundleNode(a1, v125, 0LL, 0LL, 0LL, 0LL, 0LL);
      objc_release(v125);
      if ( !v127 )
      {
LABEL_171:
        v769 = v125;
        goto LABEL_172;
      }
      v129 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v128));
      if ( j__os_log_type_enabled_3(v129, OS_LOG_TYPE_ERROR) )
      {
        *v822 = 134217984;
        *&v822[4] = v127;
        j___os_log_impl_1(
          &dword_180981000,
          v129,
          OS_LOG_TYPE_ERROR,
          "LAUNCH:pre-registering translocated app node failed, optimistically continuing anyway: %ld",
          v822,
          0xCu);
      }
      v130 = v129;
    }
    else
    {
      v130 = v125;
    }
    objc_release(v130);
    goto LABEL_171;
  }
  v118 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v117));
  if ( j__os_log_type_enabled_3(v118, OS_LOG_TYPE_ERROR) )
  {
    v119 = objc_retain(objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, *(v796 + 6))));
    v120 = objc_retainAutoreleasedReturnValue(objc_msgSend(v107, "URL"));
    *v822 = 138543875;
    *&v822[4] = v119;
    *&v822[12] = 2113;
    *&v822[14] = v120;
    *&v822[22] = 2114;
    *&v822[24] = v116;
    j___os_log_impl_1(
      &dword_180981000,
      v118,
      OS_LOG_TYPE_ERROR,
      "LAUNCH:translocate failed, %{public}@ %{private}@, error=%{public}@",
      v822,
      0x20u);
    objc_release(v120);
    objc_release(v119);
    objc_release(v119);
  }
  objc_release(v118);
  if ( a14 )
  {
    v772 = objc_retainAutorelease(v116);
    *a14 = v772;
    goto LABEL_173;
  }
LABEL_172:
  v772 = v116;
LABEL_173:
  if ( *(v800 + 6) )
  {
    v763 = 0LL;
  }
  else
  {
    v791 = v772;
    v131 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "pathWithError:", &v791));
    v132 = objc_retain(v791);
    objc_release(v772);
    v763 = v131;
    if ( !v131 )
    {
      v134 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v133));
      if ( j__os_log_type_enabled_3(v134, OS_LOG_TYPE_ERROR) )
      {
        v135 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
        *v822 = 138478083;
        *&v822[4] = v135;
        *&v822[12] = 2114;
        *&v822[14] = v132;
        j___os_log_impl_1(
          &dword_180981000,
          v134,
          OS_LOG_TYPE_ERROR,
          "LAUNCH:Unable to determine path for bundle, node=%{private}@ error=%{public}@",
          v822,
          0x16u);
        objc_release(v135);
      }
      objc_release(v134);
      v136 = _LSGetOSStatusFromNSError(v132);
      *(v800 + 6) = v136;
      if ( a14 )
      {
        v763 = 0LL;
        v772 = objc_retainAutorelease(v132);
        *a14 = v772;
        goto LABEL_181;
      }
      v763 = 0LL;
    }
    v772 = v132;
  }
LABEL_181:
  if ( (v775 & 0x80008) != 8 || *(v800 + 6) )
    goto LABEL_190;
  v137 = objc_retain(v769);
  v138 = v137;
  if ( !a11 )
    goto LABEL_189;
  v139 = objc_retainAutoreleasedReturnValue(objc_msgSend(v137, "pathWithError:", 0LL));
  if ( !v139 || (v140 = _LSCopyApplicationsWithPath(4294967294LL, v139), (v141 = v140) == 0LL) )
  {
    objc_release(v139);
LABEL_189:
    objc_release(v138);
    goto LABEL_190;
  }
  if ( j__CFArrayGetCount(v140) < 1 )
    v142 = 0LL;
  else
    v142 = j__CFRetain(v141);
  j__CFRelease(v141);
  objc_release(v139);
  if ( !v142 )
    goto LABEL_189;
  Count = j__CFArrayGetCount(v142);
  if ( Count < 1 )
  {
    v198 = 0;
  }
  else
  {
    v197 = 0LL;
    v198 = 0;
    do
    {
      ValueAtIndex = j__CFArrayGetValueAtIndex(v142, v197);
      v200 = _LSGetPIDFromToken(a11);
      if ( v200 == j__getpid_8() )
      {
        v201 = _LSGetCurrentApplicationASN();
        v198 = j__CFEqual(ValueAtIndex, v201) != 0;
      }
      else
      {
        v202 = _LSCopyApplicationInformationItem(4294967294LL, ValueAtIndex, CFSTR("pid"));
        v203 = v202;
        if ( v202 )
        {
          *v822 = 0LL;
          Value = j__CFNumberGetValue(v202, kCFNumberLongLongType, v822);
          v205 = *v822;
          v206 = _LSGetPIDFromToken(a11);
          if ( Value )
            v207 = v205;
          else
            v207 = 0;
          v198 = v206 == v207;
          j__CFRelease(v203);
        }
      }
      ++v197;
    }
    while ( v197 < Count && !v198 );
  }
  j__CFRelease(v142);
  objc_release(v138);
  if ( v198 )
  {
    v209 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v208));
    if ( j__os_log_type_enabled_3(v209, OS_LOG_TYPE_INFO) )
    {
      v210 = objc_retain(objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, *(v796 + 6))));
      v211 = objc_retainAutoreleasedReturnValue(objc_msgSend(v138, "URL"));
      *v822 = 138543619;
      *&v822[4] = v210;
      *&v822[12] = 2113;
      *&v822[14] = v211;
      j___os_log_impl_1(
        &dword_180981000,
        v209,
        OS_LOG_TYPE_INFO,
        "LAUNCH:Launch request matches current application and has kLSLaunchProbitSelf, and not kLSLaunchNewInstance, so "
        "failing with err=kLSSelfProhibitedErr, path=%{public}@ %{private}@",
        v822,
        0x16u);
      objc_release(v211);
      objc_release(v210);
      objc_release(v210);
    }
    objc_release(v209);
    *(v800 + 6) = -10653;
  }
LABEL_190:
  v143 = *(v800 + 6);
  if ( (!v143 || v143 == -10668) && (v775 & 0x4000000) != 0 )
  {
    v144 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
    if ( v794 )
    {
      v145 = objc_retainAutoreleasedReturnValue(objc_msgSend(v770, "URL"));
      objc_release(v144);
      v144 = v145;
    }
    v146 = objc_retain(v144);
    SPExecutionPolicyClass = getSPExecutionPolicyClass();
    v148 = j__objc_opt_new_0(SPExecutionPolicyClass);
    if ( a6 )
    {
      LODWORD(v817) = 0;
      LODWORD(v815) = 0;
      if ( _LSGetAppleEventClassAndID(a6, &v817, &v815) )
      {
        if ( v817 == 1634039412 && v815 == 1868853091 )
        {
          DWORD2(v821[0]) = 0;
          *&v821[0] = 0LL;
          v149 = AEGetParamDesc(a6, 0x2D2D2D2Du, 0x6C697374u, v821);
          if ( !v149 )
          {
            *v822 = &OBJC_CLASS_____NSStackBlock__;
            *&v822[8] = 3254779904LL;
            *&v822[16] = ___ZL46notifySyspolicydAboutUnsignedApplicationLaunchPK6AEDescP5NSURL_block_invoke;
            *&v822[24] = &__block_descriptor_40_ea8_32s_e49_i24__0r__AEDesc_I___OpaqueAEDataStorageType__8q16l;
            *&v822[32] = objc_retain(v148);
            v149 = _LSEnumerateAEDescList(v821, 707406378LL, v822);
            AEDisposeDesc(v821);
            objc_release(*&v822[32]);
          }
          if ( v149 )
          {
            *&v819 = 0LL;
            _LSGetNSErrorFromOSStatusImpl(v149, &v819, "notifySyspolicydAboutUnsignedApplicationLaunch", 1360LL);
            v150 = objc_retain(v819);
            v151 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v150));
            if ( j__os_log_type_enabled_3(v151, OS_LOG_TYPE_INFO) )
            {
              LODWORD(v835[0]) = 67240450;
              DWORD1(v835[0]) = v149;
              WORD4(v835[0]) = 2112;
              *(v835 + 10) = v150;
              j___os_log_impl_1(
                &dword_180981000,
                v151,
                OS_LOG_TYPE_INFO,
                "LAUNCH: Could not inspect contents of odoc AppleEvent: %{public}d %@",
                v835,
                0x12u);
            }
            objc_release(v151);
            objc_release(v150);
          }
        }
      }
    }
    *&v821[0] = 0LL;
    v152 = objc_msgSend(v148, "addGatekeeperUserIntent:error:", v146, v821);
    v153 = objc_retain(*&v821[0]);
    v154 = v153;
    if ( v152 )
    {
      v155 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v153));
      if ( j__os_log_type_enabled_3(v155, OS_LOG_TYPE_DEBUG) )
      {
        v156 = objc_retainAutoreleasedReturnValue(objc_msgSend(v146, "path"));
        LODWORD(v835[0]) = 138477827;
        *(v835 + 4) = v156;
        v157 = "LAUNCH:notified syspolicyd about %{private}@";
        v158 = v155;
        v159 = OS_LOG_TYPE_DEBUG;
        v160 = 12;
LABEL_210:
        j___os_log_impl_1(&dword_180981000, v158, v159, v157, v835, v160);
        objc_release(v156);
      }
    }
    else
    {
      v155 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v153));
      if ( j__os_log_type_enabled_3(v155, OS_LOG_TYPE_ERROR) )
      {
        v156 = objc_retainAutoreleasedReturnValue(objc_msgSend(v146, "path"));
        LODWORD(v835[0]) = 138478083;
        *(v835 + 4) = v156;
        WORD6(v835[0]) = 2112;
        *(v835 + 14) = v154;
        v157 = "LAUNCH: could not notify syspolicyd about %{private}@: %@";
        v158 = v155;
        v159 = OS_LOG_TYPE_ERROR;
        v160 = 22;
        goto LABEL_210;
      }
    }
    objc_release(v155);
    objc_release(v154);
    objc_release(v148);
    objc_release(v146);
    objc_release(v146);
    v143 = *(v800 + 6);
  }
  if ( v143 )
  {
    v161 = 0LL;
    goto LABEL_963;
  }
  *&v817 = 0LL;
  *(&v817 + 1) = &v817;
  v818 = 0x2020000000uLL;
  *(&v818 + 1) = _LSBundleGet(a1->db, *(v796 + 6));
  v753 = objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, *(v796 + 6)));
  *&v815 = 0LL;
  *(&v815 + 1) = &v815;
  *&v816 = 0x2020000000LL;
  BYTE8(v816) = 0;
  v163 = *(*(&v817 + 1) + 24LL);
  if ( v163 && (*(v163 + 158) & 0x80) != 0 )
  {
    v183 = objc_retainAutoreleasedReturnValue(_LSPlistGetValueForKey(
                                                a1->db,
                                                *(v163 + 120),
                                                CFSTR("LSTemplateApplication"),
                                                v162));
    isKindOfClass_2 = objc_retainAutoreleasedReturnValue(_LSPlistGetValueForKey(
                                                           a1->db,
                                                           *(*(*(&v817 + 1) + 24LL) + 120LL),
                                                           CFSTR("LSTemplateApplicationParameters"),
                                                           v184));
    v186 = isKindOfClass_2;
    if ( !v183
      || (isKindOfClass_2 = boolValue(v183, 0), (isKindOfClass_2 & (v186 != 0LL)) != 1)
      || (v187 = j__objc_opt_class_3(&OBJC_CLASS___NSDictionary),
          isKindOfClass_2 = j__objc_opt_isKindOfClass_2(v186, v187),
          (isKindOfClass_2 & 1) == 0) )
    {
      v195 = objc_retainAutoreleasedReturnValue(_LSOpenLog(isKindOfClass_2));
      if ( j__os_log_type_enabled_3(v195, OS_LOG_TYPE_ERROR) )
      {
        *v822 = 138477827;
        *&v822[4] = v763;
        j___os_log_impl_1(
          &dword_180981000,
          v195,
          OS_LOG_TYPE_ERROR,
          "LAUNCH: Unable to determine proxyApp parameters for template app launch of %{private}@",
          v822,
          0xCu);
      }
      objc_release(v195);
      v750 = 0LL;
      v754 = 0LL;
      *(v800 + 6) = -50;
      v190 = v772;
      goto LABEL_248;
    }
    v188 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
    v790 = v772;
    v189 = _LSTemplateApplicationCheckSignatureBeforeLaunch();
    v190 = objc_retain(v772);
    objc_release(v772);
    objc_release(v188);
    if ( !v189 )
    {
      v291 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v191));
      if ( j__os_log_type_enabled_3(v291, OS_LOG_TYPE_ERROR) )
      {
        v292 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
        *v822 = 138478083;
        *&v822[4] = v292;
        *&v822[12] = 2114;
        *&v822[14] = v190;
        j___os_log_impl_1(
          &dword_180981000,
          v291,
          OS_LOG_TYPE_ERROR,
          "LAUNCH: Launch failed because template application %{private}@ does not have permission to launch, error=%{public}@",
          v822,
          0x16u);
        objc_release(v292);
      }
      objc_release(v291);
      if ( v190 )
      {
        v293 = objc_retainAutoreleasedReturnValue(-[NSError domain](v190, "domain"));
        if ( -[NSString isEqual:](v293, "isEqual:", CFSTR("NSOSStatusErrorDomain")) )
          v294 = -[NSError code](v190, "code");
        else
          v294 = -10827;
        *(v800 + 6) = v294;
        objc_release(v293);
        v750 = 0LL;
        v754 = 0LL;
      }
      else
      {
        v750 = 0LL;
        v754 = 0LL;
        *(v800 + 6) = -10827;
      }
      goto LABEL_248;
    }
    v747 = objc_retainAutoreleasedReturnValue(objc_msgSend(v186, "objectForKeyedSubscript:", CFSTR("CFBundleIdentifier")));
    if ( v747
      && (v192 = j__objc_opt_class_3(&OBJC_CLASS___NSString), (j__objc_opt_isKindOfClass_2(v747, v192) & 1) != 0) )
    {
      v193 = -[LSApplicationRecord _initWithNode:bundleIdentifier:placeholderBehavior:systemPlaceholder:itemID:forceInBundleContainer:context:error:](
               objc_alloc(&OBJC_CLASS___LSApplicationRecord),
               "_initWithNode:bundleIdentifier:placeholderBehavior:systemPlaceholder:itemID:forceInBundleContainer:context:error:",
               0LL,
               v747,
               0LL,
               0LL,
               0LL,
               0LL,
               a1,
               0LL);
      v194 = v193;
    }
    else
    {
      v296 = objc_retainAutoreleasedReturnValue(objc_msgSend(v186, "objectForKeyedSubscript:", CFSTR("BundlePath")));
      objc_release(v747);
      if ( !v296
        || (v298 = j__objc_opt_class_3(&OBJC_CLASS___NSString),
            v297 = j__objc_opt_isKindOfClass_2(v296, v298),
            (v297 & 1) == 0) )
      {
        v302 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v297));
        if ( j__os_log_type_enabled_3(v302, OS_LOG_TYPE_ERROR) )
        {
          *v822 = 138477827;
          *&v822[4] = v763;
          j___os_log_impl_1(
            &dword_180981000,
            v302,
            OS_LOG_TYPE_ERROR,
            "LAUNCH: Unable to determine proxyApp for template app launch of %{private}@",
            v822,
            0xCu);
        }
        objc_release(v302);
        v194 = 0LL;
        *(v800 + 6) = -10674;
        v301 = 1;
        goto LABEL_652;
      }
      v747 = objc_retain(v296);
      v299 = objc_msgSend(v747, "length");
      if ( v299
        && (v299 = objc_msgSend(v747, "characterAtIndex:", 0LL), v299 == 47)
        && (v299 = objc_msgSend(v747, "containsString:", CFSTR("/..")), (v299 & 1) == 0)
        && (v299 = objc_msgSend(v747, "containsString:", CFSTR("/.")), (v299 & 1) == 0) )
      {
        v679 = objc_retainAutoreleasedReturnValue(+[NSURL fileURLWithPath:](&OBJC_CLASS___NSURL, "fileURLWithPath:", v747));
        v680 = -[FSNode initWithURL:flags:error:](
                 objc_alloc(&OBJC_CLASS___FSNode),
                 "initWithURL:flags:error:",
                 v679,
                 1LL,
                 0LL);
        v194 = -[LSApplicationRecord _initWithNode:bundleIdentifier:placeholderBehavior:systemPlaceholder:itemID:forceInBundleContainer:context:error:](
                 objc_alloc(&OBJC_CLASS___LSApplicationRecord),
                 "_initWithNode:bundleIdentifier:placeholderBehavior:systemPlaceholder:itemID:forceInBundleContainer:context:error:",
                 v680,
                 0LL,
                 0LL,
                 0LL,
                 0LL,
                 0LL,
                 a1,
                 0LL);
        objc_release(v680);
        objc_release(v679);
      }
      else
      {
        v300 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v299));
        if ( j__os_log_type_enabled_3(v300, OS_LOG_TYPE_ERROR) )
        {
          *v822 = 138478083;
          *&v822[4] = v747;
          *&v822[12] = 2113;
          *&v822[14] = v763;
          j___os_log_impl_1(
            &dword_180981000,
            v300,
            OS_LOG_TYPE_ERROR,
            "LAUNCH: Invalid BundlePath %{private}@ in template application %{private}@",
            v822,
            0x16u);
        }
        objc_release(v300);
        v194 = 0LL;
        *(v800 + 6) = -10674;
      }
      objc_release(v747);
    }
    if ( !v194 )
    {
      v301 = 1;
      goto LABEL_651;
    }
    if ( *(v800 + 6) )
    {
      v301 = 0;
LABEL_651:
      v296 = v747;
LABEL_652:
      v458 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v193));
      if ( j__os_log_type_enabled_3(v458, OS_LOG_TYPE_ERROR) )
      {
        *v822 = 138478083;
        *&v822[4] = v296;
        *&v822[12] = 2113;
        *&v822[14] = v763;
        j___os_log_impl_1(
          &dword_180981000,
          v458,
          OS_LOG_TYPE_ERROR,
          "LAUNCH: Cannot find proxy-app record, path=%{private}@ in template application %{private}@",
          v822,
          0x16u);
      }
      objc_release(v458);
      v754 = 0LL;
      *(v800 + 6) = -10674;
      v747 = v296;
      goto LABEL_655;
    }
    v667 = objc_msgSend(v194, "isTemplateProxyApplication");
    if ( (v667 & 1) == 0 )
    {
      v674 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v667));
      if ( j__os_log_type_enabled_3(v674, OS_LOG_TYPE_ERROR) )
      {
        v675 = objc_retainAutoreleasedReturnValue(objc_msgSend(v194, "URL"));
        *v822 = 138477827;
        *&v822[4] = v675;
        j___os_log_impl_1(
          &dword_180981000,
          v674,
          OS_LOG_TYPE_ERROR,
          "LAUNCH: Template-proxy application %{private}@ is not properly specified.",
          v822,
          0xCu);
        objc_release(v675);
      }
      objc_release(v674);
      v301 = 0;
      v754 = 0LL;
      *(v800 + 6) = -10674;
      goto LABEL_655;
    }
    if ( *(v800 + 6) )
      goto LABEL_976;
    v676 = objc_msgSend(v194, "isLaunchDisabled");
    if ( v676 )
    {
      v742 = v186;
      v746 = v194;
      v738 = v190;
      v677 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v676));
      if ( j__os_log_type_enabled_3(v677, OS_LOG_TYPE_ERROR) )
      {
        v678 = objc_retainAutoreleasedReturnValue(objc_msgSend(v194, "URL"));
        *v822 = 138477827;
        *&v822[4] = v678;
        j___os_log_impl_1(
          &dword_180981000,
          v677,
          OS_LOG_TYPE_ERROR,
          "LAUNCH: Launch of template-proxy-app %{private}@ is disabled, so failing.",
          v822,
          0xCu);
        objc_release(v678);
      }
      objc_release(v677);
      v301 = 0;
      v754 = 0LL;
      *(v800 + 6) = -10674;
    }
    else
    {
      if ( *(v800 + 6) )
      {
LABEL_976:
        v301 = 0;
        v754 = 0LL;
        goto LABEL_655;
      }
      v738 = v190;
      v742 = v186;
      v746 = v194;
      v683 = objc_retainAutoreleasedReturnValue(objc_msgSend(v194, "executableURL"));
      v684 = v683;
      if ( v683
        && (v683 = objc_msgSend(v683, "isFileURL"), v683)
        && (v685 = objc_retainAutorelease(v684), (v683 = objc_msgSend(v685, "fileSystemRepresentation")) != 0LL) )
      {
        v754 = objc_retainAutoreleasedReturnValue(
                 +[NSString stringWithUTF8String:](
                   &OBJC_CLASS___NSString,
                   "stringWithUTF8String:",
                   objc_msgSend(objc_retainAutorelease(v685), "fileSystemRepresentation")));
        v686 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v754));
        if ( j__os_log_type_enabled_3(v686, OS_LOG_TYPE_INFO) )
        {
          v687 = objc_retainAutoreleasedReturnValue(objc_msgSend(v194, "bundleIdentifier"));
          *v822 = 138478339;
          *&v822[4] = v763;
          *&v822[12] = 2114;
          *&v822[14] = v687;
          *&v822[22] = 2113;
          *&v822[24] = v754;
          j___os_log_impl_1(
            &dword_180981000,
            v686,
            OS_LOG_TYPE_INFO,
            "LAUNCH: Substituting executable for %{private}@, new executable bundleID is %{public}@ path=%{private}@",
            v822,
            0x20u);
          objc_release(v687);
        }
        objc_release(v686);
      }
      else
      {
        v700 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v683));
        if ( j__os_log_type_enabled_3(v700, OS_LOG_TYPE_ERROR) )
        {
          v701 = objc_retainAutoreleasedReturnValue(objc_msgSend(v194, "URL"));
          *v822 = 138477827;
          *&v822[4] = v701;
          j___os_log_impl_1(
            &dword_180981000,
            v700,
            OS_LOG_TYPE_ERROR,
            "LAUNCH: Launch of template-proxy-app %{private}@ can't determine proxyApp executable, so failing.",
            v822,
            0xCu);
          objc_release(v701);
        }
        objc_release(v700);
        v754 = 0LL;
        *(v800 + 6) = -10674;
      }
      objc_release(v684);
      if ( !*(v800 + 6) )
      {
        v785[0] = &OBJC_CLASS_____NSStackBlock__;
        v785[1] = 3254779904LL;
        v785[2] = ___ZL25_LSLaunchWithRunningboardP9LSContextP6FSNodejPvPK9__CFArrayPK6AEDescS9_P7NSArrayIP11LSSliceInfoEPK14__CFDictionaryjPK13audit_token_tPK15_LSOpen2OptionsP19ProcessSerialNumberPU15__autoreleasingP7NSError_block_invoke;
        v785[3] = &__block_descriptor_64_ea8_32s40r48r56r_e32_v32__0__LSContext___8I16I20r_v24l;
        v787 = &v795;
        v788 = &v817;
        v786 = objc_retain(v763);
        v789 = &v815;
        v784[0] = &OBJC_CLASS_____NSStackBlock__;
        v784[1] = 3254779904LL;
        v784[2] = ___ZL25_LSLaunchWithRunningboardP9LSContextP6FSNodejPvPK9__CFArrayPK6AEDescS9_P7NSArrayIP11LSSliceInfoEPK14__CFDictionaryjPK13audit_token_tPK15_LSOpen2OptionsP19ProcessSerialNumberPU15__autoreleasingP7NSError_block_invoke_126;
        v784[3] = &__block_descriptor_40_ea8_32r_e5_v8__0l;
        v784[4] = &v799;
        objc_msgSend(v194, "_ifAttached:else:", v785, v784);
        objc_release(v786);
      }
      v301 = 0;
    }
    v190 = v738;
    v186 = v742;
    v194 = v746;
LABEL_655:
    v773 = j__objc_opt_new_0(&OBJC_CLASS___NSMutableArray);
    if ( (v301 & 1) == 0 )
    {
      v459 = objc_retainAutoreleasedReturnValue(objc_msgSend(v194, "infoDictionary"));
      objc_release(v459);
      if ( v459 )
      {
        v460 = objc_retainAutoreleasedReturnValue(objc_msgSend(v194, "infoDictionary"));
        v461 = objc_retainAutoreleasedReturnValue(
                 objc_msgSend(
                   v460,
                   "objectForKey:ofClass:",
                   CFSTR("LSTemplateProxyApplicationParameters"),
                   j__objc_opt_class_3(&OBJC_CLASS___NSDictionary)));
        objc_release(v460);
        if ( v461 )
        {
          v462 = objc_retainAutoreleasedReturnValue(objc_msgSend(v461, "objectForKeyedSubscript:", CFSTR("defaultarguments")));
          v463 = boolValue(v462, 1);
          objc_release(v462);
          if ( !v463 )
            goto LABEL_666;
        }
        v464 = v763;
        if ( v763 )
        {
          v812[0] = CFSTR("--bundlepath");
          v812[1] = v763;
          v465 = objc_retainAutoreleasedReturnValue(+[NSArray arrayWithObjects:count:](&OBJC_CLASS___NSArray, "arrayWithObjects:count:", v812, 2LL));
          -[NSMutableArray addObjectsFromArray:](v773, "addObjectsFromArray:", v465);
          objc_release(v465);
          v464 = v763;
        }
        v466 = objc_retainAutoreleasedReturnValue(sandboxExtensionForPath(v464));
        v467 = v466;
        if ( v466 )
        {
          v811[0] = CFSTR("--sandboxextension");
          v811[1] = v466;
          v468 = objc_retainAutoreleasedReturnValue(+[NSArray arrayWithObjects:count:](&OBJC_CLASS___NSArray, "arrayWithObjects:count:", v811, 2LL));
          -[NSMutableArray addObjectsFromArray:](v773, "addObjectsFromArray:", v468);
          objc_release(v468);
        }
        objc_release(v467);
        if ( v753 )
        {
          v810[0] = CFSTR("--bundleidentifier");
          v810[1] = v753;
          v469 = objc_retainAutoreleasedReturnValue(+[NSArray arrayWithObjects:count:](&OBJC_CLASS___NSArray, "arrayWithObjects:count:", v810, 2LL));
          -[NSMutableArray addObjectsFromArray:](v773, "addObjectsFromArray:", v469);
          objc_release(v469);
        }
        -[NSMutableArray addObject:](v773, "addObject:", CFSTR("--"));
        if ( v461 )
        {
LABEL_666:
          v470 = objc_retainAutoreleasedReturnValue(objc_msgSend(v461, "objectForKeyedSubscript:", CFSTR("arguments")));
          if ( v470 )
          {
            v471 = j__objc_opt_class_3(&OBJC_CLASS___NSArray);
            if ( (j__objc_opt_isKindOfClass_2(v470, v471) & 1) != 0 )
            {
              v751 = v461;
              v741 = v186;
              v745 = v194;
              v735 = v470;
              v737 = v190;
              v759 = a5;
              v782 = 0u;
              v783 = 0u;
              v780 = 0u;
              v781 = 0u;
              v472 = objc_retain(v470);
              v473 = objc_msgSend(v472, "countByEnumeratingWithState:objects:count:", &v780, v809, 16LL);
              if ( v473 )
              {
                if ( v753 )
                  v474 = v753;
                else
                  v474 = CFSTR("-");
                v475 = *v781;
                if ( v763 )
                  v476 = v763;
                else
                  v476 = CFSTR("-");
                do
                {
                  for ( i = 0LL; i != v473; i = i + 1 )
                  {
                    if ( *v781 != v475 )
                      j__objc_enumerationMutation_0(v472);
                    v478 = *(*(&v780 + 1) + 8LL * i);
                    v479 = j__objc_opt_class_3(&OBJC_CLASS___NSString);
                    if ( (j__objc_opt_isKindOfClass_2(v478, v479) & 1) != 0 )
                    {
                      v480 = -[__CFString isEqual:](v478, "isEqual:", CFSTR("%%BUNDLEPATH%%"));
                      v481 = v476;
                      if ( (v480 & 1) == 0 )
                      {
                        if ( -[__CFString isEqual:](v478, "isEqual:", CFSTR("%%BUNDLEPATHSANDBOXEXTENSION%%")) )
                        {
                          v482 = objc_retainAutoreleasedReturnValue(sandboxExtensionForPath(v763));
                          v483 = v482;
                          if ( v482 )
                            v484 = v482;
                          else
                            v484 = CFSTR("-");
                          -[NSMutableArray addObject:](v773, "addObject:", v484);
                          objc_release(v483);
                        }
                        if ( -[__CFString isEqual:](v478, "isEqual:", CFSTR("%%BUNDLEIDENTIFIER%%")) )
                          v481 = v474;
                        else
                          v481 = v478;
                      }
                      -[NSMutableArray addObject:](v773, "addObject:", v481);
                    }
                  }
                  v473 = objc_msgSend(v472, "countByEnumeratingWithState:objects:count:", &v780, v809, 16LL);
                }
                while ( v473 );
              }
              objc_release(v472);
              v190 = v737;
              v186 = v741;
              v194 = v745;
              v461 = v751;
              v470 = v735;
              -[NSMutableArray addObject:](v773, "addObject:", CFSTR("--"));
              a5 = v759;
            }
          }
          objc_release(v470);
        }
        if ( a5 )
          -[NSMutableArray addObjectsFromArray:](v773, "addObjectsFromArray:", a5);
        objc_release(v461);
      }
    }
    v750 = -[NSObject copy](v773, "copy");
    objc_release(v773);
    objc_release(v747);
    objc_release(v194);
LABEL_248:
    objc_release(v186);
    v161 = 0LL;
    v772 = v190;
    goto LABEL_328;
  }
  v164 = objc_retainAutoreleasedReturnValue(constructExecutablePathFromBundleData(a1, *(v796 + 6), v163, v763, v794));
  v165 = *(*(&v817 + 1) + 24LL);
  v166 = objc_retain(v753);
  v167 = objc_retain(v763);
  v754 = objc_retain(v164);
  *v814 = 0LL;
  if ( (v775 & 0x80000) != 0 || !v166 )
  {
    if ( (v775 & 0x80000) != 0 )
      goto LABEL_273;
  }
  else
  {
    v168 = objc_retain(v167);
    v169 = _LSCopyApplicationsWithPath(4294967294LL, v168);
    v170 = v169;
    if ( v169 )
    {
      if ( j__CFArrayGetCount(v169) >= 1 )
      {
        *v822 = &OBJC_CLASS_____NSStackBlock__;
        *&v822[8] = 3254779904LL;
        *&v822[16] = ___ZL56delayLaunchOfCatalystApplicationWhichMayBeExitingForABitP8NSString_block_invoke;
        *&v822[24] = &__block_descriptor_40_ea8_32s_e9_B16__0_v8l;
        *&v822[32] = objc_retain(v168);
        CFArrayApplyBlock(v170, v822);
        objc_release(*&v822[32]);
      }
      j__CFRelease(v170);
    }
    objc_release(v168);
  }
  v171 = copyExistingApplicationWithSameExecutablePath(v167, v754);
  v172 = v171;
  v173 = *v814;
  if ( *v814 != v171 )
  {
    *v814 = v171;
    v171 = v173;
  }
  if ( v171 )
  {
    j__CFRelease(v171);
    v172 = *v814;
  }
  if ( v172 )
  {
    v174 = _LSCopyApplicationInformationItem(4294967294LL, v172, CFSTR("LSApplicationWasTerminatedByTALKey"));
    if ( v174 )
    {
      TypeID = j__CFBooleanGetTypeID();
      if ( TypeID && j__CFGetTypeID(v174) != TypeID )
      {
        j__CFRelease(v174);
      }
      else
      {
        v176 = j__CFBooleanGetValue(v174);
        j__CFRelease(v174);
        if ( v176 )
        {
          v178 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v177));
          if ( j__os_log_type_enabled_3(v178, OS_LOG_TYPE_DEBUG) )
          {
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(v172, v835, 0LL);
            v179 = v835[0];
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(v172, 0LL, v835);
            *v822 = 67240448;
            *&v822[4] = v179;
            *&v822[8] = 1026;
            *&v822[10] = v835[0];
            j___os_log_impl_1(
              &dword_180981000,
              v178,
              OS_LOG_TYPE_DEBUG,
              "LAUNCH: Application 0x%{public}x-0x%{public}x is applicationIsTALTerminated.",
              v822,
              0xEu);
          }
          objc_release(v178);
          v181 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v180));
          if ( j__os_log_type_enabled_3(v181, OS_LOG_TYPE_DEBUG) )
          {
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(*v814, v835, 0LL);
            v182 = v835[0];
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(*v814, 0LL, v835);
            *v822 = 67240706;
            *&v822[4] = v182;
            *&v822[8] = 1026;
            *&v822[10] = v835[0];
            *&v822[14] = 2114;
            *&v822[16] = v167;
            j___os_log_impl_1(
              &dword_180981000,
              v181,
              OS_LOG_TYPE_DEBUG,
              "LAUNCH: Launching previously tal-terminated applications, 0x%{public}x-0x%{public}x/node=%{public}@.",
              v822,
              0x18u);
          }
          objc_release(v181);
          goto LABEL_273;
        }
      }
    }
    v212 = _LSIsApplicationRunning(4294967294LL, *v814);
    if ( v212 )
    {
      v213 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v212));
      if ( j__os_log_type_enabled_3(v213, OS_LOG_TYPE_DEBUG) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(*v814, v835, 0LL);
        v214 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(*v814, 0LL, v835);
        *v822 = 67240706;
        *&v822[4] = v214;
        *&v822[8] = 1026;
        *&v822[10] = v835[0];
        *&v822[14] = 2114;
        *&v822[16] = v167;
        v215 = "LAUNCH: Application is already running, 0x%{public}x-0x%{public}x, so not launching it again, %{public}@.";
        v216 = v213;
        v217 = OS_LOG_TYPE_DEBUG;
        v218 = 24;
LABEL_307:
        j___os_log_impl_1(&dword_180981000, v216, v217, v215, v822, v218);
      }
LABEL_308:
      objc_release(v213);
      v230 = -10652;
      goto LABEL_310;
    }
  }
LABEL_273:
  if ( !v165 )
    goto LABEL_309;
  if ( (*(v165 + 148) & 0x20) == 0 )
    goto LABEL_281;
  v219 = *v814;
  *v814 = 0LL;
  if ( v219 )
    j__CFRelease(v219);
  v220 = checkForMultipleLaunchProhibitedApplication(v166, v814);
  if ( !v220 )
  {
LABEL_281:
    v222 = *(v165 + 20);
    if ( v222 == 2 )
    {
      v231 = *v814;
      *v814 = 0LL;
      if ( v231 )
        j__CFRelease(v231);
      v232 = isBundleIdentifierAlreadyRunning(v166, v814);
      if ( v232 )
      {
        if ( (v775 & 0x80000) == 0 )
        {
          v213 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v232));
          if ( !j__os_log_type_enabled_3(v213, OS_LOG_TYPE_ERROR) )
            goto LABEL_308;
LABEL_306:
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(*v814, v835, 0LL);
          v235 = v835[0];
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(*v814, 0LL, v835);
          *v822 = 138544131;
          *&v822[4] = v166;
          *&v822[12] = 1026;
          *&v822[14] = v235;
          *&v822[18] = 1026;
          *&v822[20] = v835[0];
          *&v822[24] = 2113;
          *&v822[26] = v167;
          v215 = "LAUNCH: Platform restriction prohibiting additional launch of %{public}@, 0x%{public}x-0x%{public}x from %{private}@";
          v216 = v213;
          v217 = OS_LOG_TYPE_ERROR;
          v218 = 34;
          goto LABEL_307;
        }
        v295 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v232));
        if ( j__os_log_type_enabled_3(v295, OS_LOG_TYPE_ERROR) )
          goto LABEL_423;
        goto LABEL_424;
      }
    }
    else if ( v222 == 6 )
    {
      if ( j___os_feature_enabled_simple_impl_1("RunningBoard", "allow_mac_multi_instance", 1LL) )
      {
        v813[0] = 0LL;
        v223 = *(v165 + 76);
        v835[0] = *(v165 + 60);
        v835[1] = v223;
        MajorComponent = _LSVersionNumberGetMajorComponent(v835);
        v225 = v813[0];
        v813[0] = 0LL;
        if ( MajorComponent < 0xF )
        {
          if ( v225 )
            j__CFRelease(v225);
          if ( isBundleIdentifierAlreadyRunning(v166, v813) )
            v230 = -10670;
          else
            v230 = 0;
        }
        else
        {
          if ( v225 )
            j__CFRelease(v225);
          if ( !isBundleIdentifierAlreadyRunning(v166, v813) )
            goto LABEL_418;
          v226 = _LSCopyApplicationInformationItem(4294967294LL, v813[0], CFSTR("LSExecutableSDKVersion"));
          v227 = CFTypeCopyAsString(v226);
          if ( v226 )
            j__CFRelease(v226);
          if ( v227 )
          {
            memset(v821, 0, sizeof(v821));
            _LSGetVersionFromString(v821, v227);
            v819 = v821[0];
            v820 = v821[1];
            v228 = _LSVersionNumberGetMajorComponent(&v819);
            if ( v228 < 0xF )
            {
              v665 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v228));
              if ( j__os_log_type_enabled_3(v665, OS_LOG_TYPE_ERROR) )
              {
                v805 = 0;
                _LSASNExtractHighAndLowParts(v813[0], &v805, 0LL);
                v666 = v805;
                v805 = 0;
                _LSASNExtractHighAndLowParts(v813[0], 0LL, &v805);
                *v822 = 138544387;
                *&v822[4] = v227;
                *&v822[12] = 2114;
                *&v822[14] = v166;
                *&v822[22] = 1026;
                *&v822[24] = v666;
                *&v822[28] = 1026;
                *&v822[30] = v805;
                *&v822[34] = 2113;
                *&v822[36] = v167;
                j___os_log_impl_1(
                  &dword_180981000,
                  v665,
                  OS_LOG_TYPE_ERROR,
                  "LAUNCH: Platform restriction prohibiting new-instance launch of Mac Catalyst pre-iOS SDK12.0 %{public}"
                  "@ %{public}@, 0x%{public}x-0x%{public}x from %{private}@",
                  v822,
                  0x2Cu);
              }
              objc_release(v665);
              v230 = -10670;
            }
            else
            {
              v229 = *v814;
              if ( *v814 )
              {
                *v814 = 0LL;
                j__CFRelease(v229);
              }
              v230 = 0;
            }
            j__CFRelease(v227);
          }
          else
          {
LABEL_418:
            v230 = 0;
          }
        }
        if ( v813[0] )
          j__CFRelease(v813[0]);
        goto LABEL_310;
      }
      v233 = *v814;
      *v814 = 0LL;
      if ( v233 )
        j__CFRelease(v233);
      v234 = isBundleIdentifierAlreadyRunning(v166, v814);
      if ( v234 )
      {
        if ( (v775 & 0x80000) == 0 )
        {
          v213 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v234));
          if ( !j__os_log_type_enabled_3(v213, OS_LOG_TYPE_ERROR) )
            goto LABEL_308;
          goto LABEL_306;
        }
        v295 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v234));
        if ( j__os_log_type_enabled_3(v295, OS_LOG_TYPE_ERROR) )
        {
LABEL_423:
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(*v814, v835, 0LL);
          v303 = v835[0];
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(*v814, 0LL, v835);
          *v822 = 138544131;
          *&v822[4] = v166;
          *&v822[12] = 1026;
          *&v822[14] = v303;
          *&v822[18] = 1026;
          *&v822[20] = v835[0];
          *&v822[24] = 2113;
          *&v822[26] = v167;
          j___os_log_impl_1(
            &dword_180981000,
            v295,
            OS_LOG_TYPE_ERROR,
            "LAUNCH: Platform restriction prohibiting new-instance launch of %{public}@, 0x%{public}x-0x%{public}x from %{private}@",
            v822,
            0x22u);
        }
LABEL_424:
        objc_release(v295);
        v230 = -10670;
        goto LABEL_310;
      }
    }
LABEL_309:
    v230 = 0;
    goto LABEL_310;
  }
  if ( *v814 )
  {
    v213 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v220));
    if ( j__os_log_type_enabled_3(v213, OS_LOG_TYPE_DEBUG) )
    {
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(*v814, v835, 0LL);
      v221 = v835[0];
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(*v814, 0LL, v835);
      *v822 = 67240448;
      *&v822[4] = v221;
      *&v822[8] = 1026;
      *&v822[10] = v835[0];
      v215 = "LAUNCH: Application 0x%{public}x-0x%{public}x already running, so will just send initial AppleEvent and act"
             "ivate if neccesary.";
      v216 = v213;
      v217 = OS_LOG_TYPE_DEBUG;
      v218 = 14;
      goto LABEL_307;
    }
    goto LABEL_308;
  }
  v290 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v220));
  if ( j__os_log_type_enabled_3(v290, OS_LOG_TYPE_ERROR) )
  {
    *v822 = 138543619;
    *&v822[4] = v166;
    *&v822[12] = 2113;
    *&v822[14] = v167;
    j___os_log_impl_1(
      &dword_180981000,
      v290,
      OS_LOG_TYPE_ERROR,
      "LAUNCH: Application %{public}@/%{private}@ already running in anther session, so returning kLSMultipleSessionsNotSupportedErr.",
      v822,
      0x16u);
  }
  objc_release(v290);
  v230 = -10829;
LABEL_310:
  v161 = *v814;
  objc_release(v754);
  objc_release(v167);
  objc_release(v166);
  *(v800 + 6) = v230;
  if ( v230 == -10652 )
  {
    if ( applicationIsStopped(v161) )
    {
      v236 = _LSCopyApplicationInformationItem(4294967294LL, v161, CFSTR("LSLaunchedInQuarantine"));
      if ( v236 )
      {
        v237 = j__CFBooleanGetTypeID();
        if ( v237 && j__CFGetTypeID(v236) != v237 )
        {
          j__CFRelease(v236);
        }
        else
        {
          v238 = j__CFBooleanGetValue(v236);
          v239 = v238;
          if ( v161 && v238 )
          {
            v240 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v238));
            if ( j__os_log_type_enabled_3(v240, OS_LOG_TYPE_DEBUG) )
            {
              LODWORD(v835[0]) = 0;
              _LSASNExtractHighAndLowParts(v161, v835, 0LL);
              v241 = v835[0];
              LODWORD(v835[0]) = 0;
              _LSASNExtractHighAndLowParts(v161, 0LL, v835);
              *v822 = 67240448;
              *&v822[4] = v241;
              *&v822[8] = 1026;
              *&v822[10] = v835[0];
              j___os_log_impl_1(
                &dword_180981000,
                v240,
                OS_LOG_TYPE_DEBUG,
                "LAUNCH: Application 0x%{public}x-0x%{public}x is launched quarantined.",
                v822,
                0xEu);
            }
            objc_release(v240);
            j__CFRelease(v236);
            goto LABEL_321;
          }
          j__CFRelease(v236);
          if ( v239 )
          {
LABEL_321:
            v243 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v242));
            if ( j__os_log_type_enabled_3(v243, OS_LOG_TYPE_ERROR) )
            {
              *v822 = 138412290;
              *&v822[4] = v167;
              j___os_log_impl_1(
                &dword_180981000,
                v243,
                OS_LOG_TYPE_ERROR,
                "LAUNCH: cannot open an app or documents for an app while it is waiting for gatekeeper approval, app=%@",
                v822,
                0xCu);
            }
            objc_release(v243);
            *(v800 + 6) = -10673;
          }
        }
      }
    }
  }
  v244 = objc_retain(a5);
  v183 = v244;
  if ( v244 )
    v750 = -[NSObject copy](v244, "copy");
  else
    v750 = 0LL;
LABEL_328:
  objc_release(v183);
  v247 = *(v800 + 6);
  if ( v247 )
  {
    v248 = 0LL;
    goto LABEL_823;
  }
  v249 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v245));
  if ( j__os_log_type_enabled_3(v249, OS_LOG_TYPE_INFO) )
  {
    v250 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
    *v822 = 138543619;
    *&v822[4] = v753;
    *&v822[12] = 2113;
    *&v822[14] = v250;
    j___os_log_impl_1(
      &dword_180981000,
      v249,
      OS_LOG_TYPE_INFO,
      "LAUNCH: _LSLaunchThruRunningboard: %{public}@ / %{private}@",
      v822,
      0x16u);
    objc_release(v250);
  }
  objc_release(v249);
  v251 = _LSBundleGet(a1->db, *(v796 + 6));
  v252 = objc_retain(v769);
  v748 = objc_retain(v763);
  v736 = objc_retain(v754);
  v739 = v252;
  v743 = objc_retain(v753);
  v758 = objc_retainAutoreleasedReturnValue(+[NSDictionary dictionary](&OBJC_CLASS___NSMutableDictionary, "dictionary"));
  v805 = 0;
  *&v819 = 0LL;
  *v814 = 0LL;
  LODWORD(v252) = objc_msgSend(v252, "getDeviceNumber:error:", &v805, v814);
  v253 = objc_retain(*v814);
  v254 = v253;
  if ( v252 )
  {
    v813[0] = v253;
    v255 = objc_msgSend(v739, "getInodeNumber:error:", &v819, v813);
    v256 = objc_retain(v813[0]);
    objc_release(v254);
    if ( (v255 & (v805 != 0)) == 1 && v819 )
    {
      v257 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:"));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v257,
        CFSTR("LSBundlePathDeviceID"));
      objc_release(v257);
      v258 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:", v819));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v258,
        CFSTR("LSBundlePathINode"));
      objc_release(v258);
      v254 = v256;
      goto LABEL_338;
    }
    v254 = v256;
  }
  v805 = 0;
  *&v819 = 0LL;
LABEL_338:
  -[NSDictionary setObject:forKeyedSubscript:](v758, "setObject:forKeyedSubscript:", v748);
  -[NSDictionary setObject:forKeyedSubscript:](v758, "setObject:forKeyedSubscript:", v736);
  if ( v251 )
  {
    if ( v805 && v819 && *(v251 + 184) == v819 && v819 == *(v251 + 192) )
    {
      v259 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:"));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v259,
        CFSTR("CFBundleExecutablePathDeviceID"));
      objc_release(v259);
      v260 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithUnsignedLongLong:](&OBJC_CLASS___NSNumber, "numberWithUnsignedLongLong:", v819));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v260,
        CFSTR("CFBundleExecutablePathINode"));
    }
    else
    {
      v261 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:"));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v261,
        CFSTR("CFBundleExecutablePathDeviceID"));
      objc_release(v261);
      v260 = objc_retainAutoreleasedReturnValue(
               +[NSNumber numberWithUnsignedLongLong:](
                 &OBJC_CLASS___NSNumber,
                 "numberWithUnsignedLongLong:",
                 *(v251 + 192)));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v260,
        CFSTR("CFBundleExecutablePathINode"));
    }
    objc_release(v260);
    v262 = _CSStringCopyCFString(a1->db->store, *(v251 + 100));
    -[NSDictionary setObject:forKeyedSubscript:](v758, "setObject:forKeyedSubscript:", v262, CFSTR("CFBundleName"));
    objc_release(v262);
    if ( v743 )
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v743,
        CFSTR("CFBundleIdentifier"));
    v263 = *(v251 + 176);
    if ( v263 && v263 != 1061109567 )
    {
      v264 = _LSCopyStringForOSType();
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v264,
        CFSTR("CFBundlePackageType"));
      objc_release(v264);
    }
    v265 = *(v251 + 180);
    if ( v265 && v265 != 1061109567 )
    {
      v266 = _LSCopyStringForOSType();
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v266,
        CFSTR("CFBundleSignature"));
      objc_release(v266);
    }
    if ( (*(v251 + 148) & 0x20) != 0 )
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        &__kCFBooleanTrue,
        CFSTR("LSMultipleInstancesProhibited"));
    v267 = objc_retainAutoreleasedReturnValue(applicationTypeKeyForBundleData(v251));
    -[NSDictionary setObject:forKeyedSubscript:](v758, "setObject:forKeyedSubscript:", v267, CFSTR("ApplicationType"));
    objc_release(v267);
    if ( (*(v251 + 148) & 0x10LL) != 0 )
      v268 = _kLSExecutableFormatPoundBangKey;
    else
      v268 = _kLSExecutableFormatMachOKey;
    -[NSDictionary setObject:forKeyedSubscript:](
      v758,
      "setObject:forKeyedSubscript:",
      *v268,
      CFSTR("LSExecutableFormat"));
    v269 = *(v251 + 148);
    if ( (v269 & 0x400) != 0 )
    {
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        &__kCFBooleanTrue,
        CFSTR("LSLaunchedInQuarantine"));
      v269 = *(v251 + 148);
    }
    if ( (v269 & 0x200000) != 0 )
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        &__kCFBooleanTrue,
        CFSTR("LSApplicationIsBetaKey"));
    if ( *(v251 + 440) )
    {
      v270 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithUnsignedLongLong:](&OBJC_CLASS___NSNumber, "numberWithUnsignedLongLong:"));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        v270,
        CFSTR("LSApplicationApplicationGenreKey"));
      objc_release(v270);
      v272 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v271));
      if ( j__os_log_type_enabled_3(v272, OS_LOG_TYPE_DEBUG) )
      {
        v273 = objc_retainAutoreleasedReturnValue(
                 +[NSNumber numberWithUnsignedLongLong:](
                   &OBJC_CLASS___NSNumber,
                   "numberWithUnsignedLongLong:",
                   *(v251 + 440)));
        *v822 = 138543875;
        *&v822[4] = v743;
        *&v822[12] = 2113;
        *&v822[14] = v748;
        *&v822[22] = 2114;
        *&v822[24] = v273;
        j___os_log_impl_1(
          &dword_180981000,
          v272,
          OS_LOG_TYPE_DEBUG,
          "LAUNCH: app %{public}@ %{private}@, genreID=%{public}@",
          v822,
          0x20u);
        objc_release(v273);
      }
      objc_release(v272);
    }
    if ( v748 && v743 && *(v251 + 524) )
    {
      v731 = -[NSURL initFileURLWithPath:isDirectory:](
               objc_alloc(&OBJC_CLASS___NSURL),
               "initFileURLWithPath:isDirectory:",
               v748,
               1LL);
      v274 = objc_retain(objc_retainAutoreleasedReturnValue(-[NSURL absoluteURL](v731, "absoluteURL")));
      v275 = objc_retain(v743);
      if ( softLinkCP_ManagedAppsIsAppManagedAtURL )
      {
        IsAppManagedAtURL = softLinkCP_ManagedAppsIsAppManagedAtURL(v274, v275);
        v727 = v275;
        objc_release(v275);
        objc_release(v274);
        objc_release(v274);
        if ( !IsAppManagedAtURL )
        {
LABEL_436:
          objc_release(v731);
          goto LABEL_437;
        }
        v278 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v277));
        if ( j__os_log_type_enabled_3(v278, OS_LOG_TYPE_INFO) )
        {
          *v822 = 138543619;
          *&v822[4] = v275;
          *&v822[12] = 2113;
          *&v822[14] = v748;
          j___os_log_impl_1(
            &dword_180981000,
            v278,
            OS_LOG_TYPE_INFO,
            "LAUNCH: app %{public}@ %{private}@ is managed, so determining an appropriate persona for launch.",
            v822,
            0x16u);
        }
        objc_release(v278);
        v279 = objc_retainAutoreleasedReturnValue(_LSDatabaseGetStringArray(a1->db, *(v251 + 524)));
        v280 = v279;
        if ( !v279 || !-[NSURL count](v279, "count") )
        {
LABEL_435:
          objc_release(v280);
          goto LABEL_436;
        }
        v836 = 0u;
        v837 = 0u;
        memset(v835, 0, sizeof(v835));
        v274 = objc_retain(v280);
        v281 = -[NSURL countByEnumeratingWithState:objects:count:](
                 v274,
                 "countByEnumeratingWithState:objects:count:",
                 v835,
                 v822,
                 16LL);
        if ( v281 )
        {
          v282 = **&v835[1];
          while ( 2 )
          {
            for ( j = 0LL; j != v281; j = j + 1 )
            {
              if ( **&v835[1] != v282 )
                j__objc_enumerationMutation_0(v274);
              v284 = objc_retain(*(*(&v835[0] + 1) + 8LL * j));
              if ( getUMUserPersonaAttributesClass() )
              {
                v285 = objc_retainAutoreleasedReturnValue(
                         objc_msgSend(
                           getUMUserPersonaAttributesClass(),
                           "personaAttributesForPersonaUniqueString:",
                           v284));
                v286 = v285;
                if ( v285 )
                {
                  v287 = objc_msgSend(v285, "userPersona_id");
                  objc_release(v286);
                  if ( v287 )
                  {
                    v304 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v288));
                    if ( j__os_log_type_enabled_3(v304, OS_LOG_TYPE_DEBUG) )
                    {
                      LODWORD(v821[0]) = 138543618;
                      *(v821 + 4) = v284;
                      WORD6(v821[0]) = 1026;
                      *(v821 + 14) = v287;
                      j___os_log_impl_1(
                        &dword_180981000,
                        v304,
                        OS_LOG_TYPE_DEBUG,
                        "LAUNCH: personaStringToUID(%{public}@ => %{public}d)",
                        v821,
                        0x12u);
                    }
                    objc_release(v304);
                    objc_release(v284);
                    v306 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v305));
                    if ( j__os_log_type_enabled_3(v306, OS_LOG_TYPE_INFO) )
                    {
                      LODWORD(v821[0]) = 138543618;
                      *(v821 + 4) = v727;
                      WORD6(v821[0]) = 1026;
                      *(v821 + 14) = v287;
                      j___os_log_impl_1(
                        &dword_180981000,
                        v306,
                        OS_LOG_TYPE_INFO,
                        "LAUNCH:45683955: Launching application %{public}@ with persona %{public}d",
                        v821,
                        0x12u);
                    }
                    objc_release(v306);
                    v275 = objc_retainAutoreleasedReturnValue(
                             +[NSNumber numberWithUnsignedLong:](
                               &OBJC_CLASS___NSNumber,
                               "numberWithUnsignedLong:",
                               v287));
                    -[NSDictionary setObject:forKeyedSubscript:](
                      v758,
                      "setObject:forKeyedSubscript:",
                      v275,
                      CFSTR("LSLaunchedPersonaUID"));
                    goto LABEL_433;
                  }
                }
              }
              objc_release(v284);
            }
            v281 = -[NSURL countByEnumeratingWithState:objects:count:](
                     v274,
                     "countByEnumeratingWithState:objects:count:",
                     v835,
                     v822,
                     16LL);
            if ( v281 )
              continue;
            break;
          }
        }
      }
      else
      {
LABEL_433:
        objc_release(v275);
      }
      objc_release(v274);
      v280 = v274;
      goto LABEL_435;
    }
  }
  else if ( (objc_msgSend(v739, "isDirectory") & 1) == 0 )
  {
    -[NSDictionary setObject:forKeyedSubscript:](
      v758,
      "setObject:forKeyedSubscript:",
      v748,
      CFSTR("CFBundleExecutablePath"));
    if ( v805 )
    {
      if ( v819 )
      {
        v289 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:"));
        -[NSDictionary setObject:forKeyedSubscript:](
          v758,
          "setObject:forKeyedSubscript:",
          v289,
          CFSTR("CFBundleExecutablePathDeviceID"));
        objc_release(v289);
        v732 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithUnsignedLongLong:](&OBJC_CLASS___NSNumber, "numberWithUnsignedLongLong:", v819));
        -[NSDictionary setObject:forKeyedSubscript:](v758, "setObject:forKeyedSubscript:");
        objc_release(v732);
      }
    }
  }
LABEL_437:
  objc_release(v254);
  objc_release(v743);
  objc_release(v736);
  objc_release(v748);
  objc_release(v739);
  v772 = objc_retain(v772);
  objc_release(v772);
  v740 = objc_retainAutoreleasedReturnValue(createLaunchModifiers(v775, a4, v307));
  if ( *(*(&v815 + 1) + 24LL) )
    -[NSDictionary setObject:forKeyedSubscript:](
      v758,
      "setObject:forKeyedSubscript:",
      &__kCFBooleanTrue,
      CFSTR("LSTemplateApplication"));
  v308 = objc_retainAutoreleasedReturnValue(objc_msgSend(v740, "valueForKey:", CFSTR("LSLaunchModifierLaunchWithASLRDisabled")));
  v733 = objc_msgSend(v308, "boolValue");
  objc_release(v308);
  if ( a6 )
    v309 = 0;
  else
    v309 = (v775 & 0x2001000) == 0;
  v310 = v309;
  if ( (v775 & 0x80000000) != 0 )
  {
    v311 = objc_retainAutoreleasedReturnValue(-[NSDictionary objectForKeyedSubscript:](v758, "objectForKeyedSubscript:", CFSTR("ApplicationType")));
    objc_msgSend(v740, "setObject:forKeyedSubscript:", v311, CFSTR("LSLaunchModifierOverriddenApplicationType"));
    objc_release(v311);
    -[NSDictionary setObject:forKeyedSubscript:](
      v758,
      "setObject:forKeyedSubscript:",
      CFSTR("BackgroundOnly"),
      CFSTR("ApplicationType"));
  }
  v312 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideApplicationType](v765, "overrideApplicationType"));
  objc_release(v312);
  if ( v312 )
  {
    v313 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideApplicationType](v765, "overrideApplicationType"));
    v314 = objc_retainAutoreleasedReturnValue(-[NSDictionary objectForKeyedSubscript:](v758, "objectForKeyedSubscript:", CFSTR("ApplicationType")));
    v315 = -[NSString isEqual:](v313, "isEqual:", v314);
    objc_release(v314);
    objc_release(v313);
    if ( (v315 & 1) == 0 )
    {
      v316 = objc_retainAutoreleasedReturnValue(-[NSDictionary objectForKeyedSubscript:](v758, "objectForKeyedSubscript:", CFSTR("ApplicationType")));
      objc_msgSend(v740, "setObject:forKeyedSubscript:", v316, CFSTR("LSLaunchModifierOverriddenApplicationType"));
      objc_release(v316);
      v317 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideApplicationType](v765, "overrideApplicationType"));
      -[NSDictionary setObject:forKeyedSubscript:](v758, "setObject:forKeyedSubscript:", v317, CFSTR("ApplicationType"));
      objc_release(v317);
    }
  }
  if ( (v775 & 0x80000000) != 0 )
  {
    v318 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideBackgroundPriorityName](v765, "overrideBackgroundPriorityName"));
    if ( v318 )
    {
      objc_release(v318);
    }
    else
    {
      v319 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options launchReason](v765, "launchReason"));
      objc_release(v319);
      if ( !v319 )
        goto LABEL_458;
    }
    v320 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideBackgroundPriorityName](v765, "overrideBackgroundPriorityName"));
    v321 = v320;
    if ( v320 )
      v322 = v320;
    else
      v322 = &stru_1ED1C6B98;
    -[NSDictionary setObject:forKeyedSubscript:](
      v758,
      "setObject:forKeyedSubscript:",
      v322,
      CFSTR("LSApplicationOverriddenBackgroundDomainName"));
    objc_release(v321);
  }
LABEL_458:
  v323 = -[_LSOpen2Options notRelaunchedForTAL](v765, "notRelaunchedForTAL");
  if ( v323 )
    v323 = -[NSDictionary setObject:forKeyedSubscript:](
             v758,
             "setObject:forKeyedSubscript:",
             &__kCFBooleanTrue,
             CFSTR("LSApplicationShouldNotBeRelaunchedByTAL"));
  v324 = (v775 >> 25) & 1;
  v325 = *(*(&v817 + 1) + 24LL);
  if ( v325 && !(((*(v325 + 150) & 0x20) == 0) | (v775 >> 25) & 1 | (v775 >> 12) & 1) )
  {
    v326 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v323));
    if ( j__os_log_type_enabled_3(v326, OS_LOG_TYPE_DEBUG) )
    {
      *v822 = 138543362;
      *&v822[4] = v743;
      j___os_log_impl_1(
        &dword_180981000,
        v326,
        OS_LOG_TYPE_DEBUG,
        "LAUNCH: launching beta app %{public}@ in stopped state",
        v822,
        0xCu);
    }
    objc_release(v326);
    objc_msgSend(v740, "setObject:forKeyedSubscript:", &__kCFBooleanTrue, CFSTR("LSLaunchStopped"));
    v722 = 1;
  }
  else
  {
    v722 = 0;
  }
  if ( v794 )
  {
    v327 = objc_retain(v758);
    v328 = objc_retain(v770);
    v329 = objc_retainAutoreleasedReturnValue(objc_msgSend(v328, "pathWithError:", 0LL));
    if ( v329 )
      -[NSDictionary setObject:forKeyedSubscript:](
        v327,
        "setObject:forKeyedSubscript:",
        v329,
        CFSTR("LSLaunchBeforeTranslocationLaunchBundlePathKey"));
    objc_release(v329);
    LODWORD(v821[0]) = 0;
    if ( objc_msgSend(v328, "getDeviceNumber:error:", v821, 0LL) )
    {
      v330 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:", SLODWORD(v821[0])));
      -[NSDictionary setObject:forKeyedSubscript:](
        v327,
        "setObject:forKeyedSubscript:",
        v330,
        CFSTR("LSLaunchBeforeTranslocationLaunchBundlePathDeviceIDKey"));
      objc_release(v330);
    }
    *v822 = 0LL;
    if ( objc_msgSend(v328, "getInodeNumber:error:", v822, 0LL) )
    {
      v331 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithUnsignedLongLong:](&OBJC_CLASS___NSNumber, "numberWithUnsignedLongLong:", *v822));
      -[NSDictionary setObject:forKeyedSubscript:](
        v327,
        "setObject:forKeyedSubscript:",
        v331,
        CFSTR("LSLaunchBeforeTranslocationLaunchBundlePathINodeKey"));
      objc_release(v331);
    }
    v332 = objc_msgSend(v328, "copyCFBundleWithError:", 0LL);
    v333 = v332;
    if ( v332 )
    {
      v334 = j__CFBundleCopyExecutableURL(v332);
      v335 = v334
           ? -[FSNode initWithURL:flags:error:](
               objc_alloc(&OBJC_CLASS___FSNode),
               "initWithURL:flags:error:",
               v334,
               0LL,
               0LL)
           : 0LL;
      objc_release(v334);
      j__CFRelease(v333);
      if ( v335 )
      {
        v336 = objc_retainAutoreleasedReturnValue(-[FSNode pathWithError:](v335, "pathWithError:", 0LL));
        if ( v336 )
          -[NSDictionary setObject:forKeyedSubscript:](
            v327,
            "setObject:forKeyedSubscript:",
            v336,
            CFSTR("LSLaunchBeforeTranslocationLaunchExecutablePathKey"));
        objc_release(v336);
        LODWORD(v819) = 0;
        if ( -[FSNode getDeviceNumber:error:](v335, "getDeviceNumber:error:", &v819, 0LL) )
        {
          v337 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:", v819));
          -[NSDictionary setObject:forKeyedSubscript:](
            v327,
            "setObject:forKeyedSubscript:",
            v337,
            CFSTR("LSLaunchBeforeTranslocationExecutablePathDeviceID"));
          objc_release(v337);
        }
        *&v835[0] = 0LL;
        if ( -[FSNode getInodeNumber:error:](v335, "getInodeNumber:error:", v835, 0LL) )
        {
          v338 = objc_retainAutoreleasedReturnValue(
                   +[NSNumber numberWithUnsignedLongLong:](
                     &OBJC_CLASS___NSNumber,
                     "numberWithUnsignedLongLong:",
                     *&v835[0]));
          -[NSDictionary setObject:forKeyedSubscript:](
            v327,
            "setObject:forKeyedSubscript:",
            v338,
            CFSTR("LSLaunchBeforeTranslocationExecutablePathINode"));
          objc_release(v338);
        }
        objc_release(v335);
      }
    }
    objc_release(v328);
    objc_release(v327);
    v324 = (v775 >> 25) & 1;
  }
  if ( !*(v800 + 6) && isForegroundApplication(v758) )
  {
    if ( (v775 & 0x100200) != 0 )
    {
      v339 = -[NSDictionary setObject:forKeyedSubscript:](
               v758,
               "setObject:forKeyedSubscript:",
               &__kCFBooleanTrue,
               CFSTR("LSLaunchDoNotBringFrontmost"));
      if ( (v775 & 0x100000) != 0 )
      {
        v340 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v339));
        if ( j__os_log_type_enabled_3(v340, OS_LOG_TYPE_DEBUG) )
        {
          *v822 = 138543362;
          *&v822[4] = v743;
          j___os_log_impl_1(
            &dword_180981000,
            v340,
            OS_LOG_TYPE_DEBUG,
            "LAUNCH: Setting up launched app to hide itself forward at registration, app=%{public}@",
            v822,
            0xCu);
        }
        objc_release(v340);
        -[NSDictionary setObject:forKeyedSubscript:](
          v758,
          "setObject:forKeyedSubscript:",
          &__kCFBooleanTrue,
          CFSTR("LSLaunchedHidden"));
      }
    }
    else
    {
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        &__kCFBooleanFalse,
        CFSTR("LSLaunchDoNotBringFrontmost"));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        &__kCFBooleanTrue,
        CFSTR("LSWantsToComeForwardAtRegistrationTimeKey"));
      -[NSDictionary setObject:forKeyedSubscript:](
        v758,
        "setObject:forKeyedSubscript:",
        _LSCopyMetaApplicationInformationItem(4294967294LL, CFSTR("LSFrontApplicationSeed")),
        CFSTR("LSFrontApplicationSeed"));
      v341 = -[NSDictionary setObject:forKeyedSubscript:](
               v758,
               "setObject:forKeyedSubscript:",
               _LSCopyMetaApplicationInformationItem(4294967294LL, CFSTR("LSUserActivityCount")),
               CFSTR("LSUserActivityCount"));
      v342 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v341));
      if ( j__os_log_type_enabled_3(v342, OS_LOG_TYPE_DEBUG) )
      {
        v343 = objc_retainAutoreleasedReturnValue(
                 -[NSDictionary objectForKeyedSubscript:](
                   v758,
                   "objectForKeyedSubscript:",
                   CFSTR("LSFrontApplicationSeed")));
        v344 = objc_retainAutoreleasedReturnValue(
                 -[NSDictionary objectForKeyedSubscript:](
                   v758,
                   "objectForKeyedSubscript:",
                   CFSTR("LSUserActivityCount")));
        *v822 = 138543874;
        *&v822[4] = v343;
        *&v822[12] = 2114;
        *&v822[14] = v344;
        *&v822[22] = 2114;
        *&v822[24] = v743;
        j___os_log_impl_1(
          &dword_180981000,
          v342,
          OS_LOG_TYPE_DEBUG,
          "LAUNCH: Setting up launched app to bring itself forward at registration, seed=%{public}@ userActitityCount=%{p"
          "ublic}@ app=%{public}@",
          v822,
          0x20u);
        objc_release(v344);
        objc_release(v343);
      }
      objc_release(v342);
    }
  }
  if ( !*(v800 + 6) )
  {
    v710 = v324;
    v725 = *(v796 + 6);
    v346 = *(*(&v817 + 1) + 24LL);
    v728 = objc_retain(v770);
    v347 = objc_retain(v764);
    v348 = v347;
    v711 = v310;
    if ( v347 )
    {
      v349 = objc_msgSend(v347, "copy");
      if ( !v346 )
        goto LABEL_526;
    }
    else
    {
      if ( !v346 )
        goto LABEL_507;
      if ( (*(v346 + 148) & 0x10) == 0 )
      {
        *&v835[0] = 0LL;
        *(&v835[0] + 1) = v835;
        *&v835[1] = 0x2020000000LL;
        DWORD2(v835[1]) = 0;
        *v822 = &OBJC_CLASS_____NSStackBlock__;
        *&v822[8] = 3254779904LL;
        *&v822[16] = ___ZL29numberOfArchitecturesInBundlePK12LSBundleData_block_invoke;
        *&v822[24] = &__block_descriptor_40_ea8_32r_e26_v24__0_LSSliceData_ii_8_16l;
        *&v822[32] = v835;
        _LSEnumerateSliceMask(*(v346 + 140), v822);
        v350 = *(*(&v835[0] + 1) + 24LL);
        j___Block_object_dispose_6(v835, 8);
        if ( v350 < 2 )
        {
LABEL_507:
          v349 = 0LL;
          goto LABEL_536;
        }
      }
      if ( (*(v346 + 156) & 0xC) != 0 )
        v351 = _LSBundleCopyArchitecturesValidOnCurrentSystem(a1->db, v725);
      else
        v351 = 0LL;
      v352 = objc_retainAutoreleasedReturnValue(_LSGetArchitecturesArrayWithUserPreference(v351, v728));
      objc_release(v351);
      if ( v352 )
      {
        v353 = objc_retain(v352);
        v354 = objc_alloc_init(&OBJC_CLASS___NSMutableArray);
        *v822 = &OBJC_CLASS_____NSStackBlock__;
        *&v822[8] = 3254779904LL;
        *&v822[16] = ___ZL37arrayOfSliceInfosFromLSCPUTypeStringsP7NSArrayIP8NSStringE_block_invoke;
        *&v822[24] = &__block_descriptor_40_ea8_32s_e25_v32__0__NSString_8Q16_B24l;
        v355 = objc_retain(v354);
        *&v822[32] = v355;
        objc_msgSend(v353, "enumerateObjectsUsingBlock:", v822);
        v349 = -[NSObject copy](v355, "copy");
        objc_release(*&v822[32]);
        objc_release(v355);
        objc_release(v353);
      }
      else
      {
        v349 = 0LL;
      }
      objc_release(v352);
    }
    if ( v349 )
    {
      if ( (*(v346 + 173) & 0x10) == 0 || _LSGetCPUType() != 16777228 )
      {
LABEL_528:
        if ( !-[NSArray count](v349, "count") )
        {
          v362 = objc_retainAutoreleasedReturnValue(_LSOpenLog(0LL));
          if ( j__os_log_type_enabled_3(v362, OS_LOG_TYPE_ERROR) )
          {
            v363 = &v819;
            asString(v348);
            if ( SBYTE7(v820) < 0 )
              v363 = v819;
            v364 = objc_retainAutoreleasedReturnValue(bundleIdentifierForBundleID(a1, v725));
            v365 = objc_retainAutoreleasedReturnValue(objc_msgSend(v728, "URL"));
            LODWORD(v821[0]) = 136446723;
            *(v821 + 4) = v363;
            WORD6(v821[0]) = 2114;
            *(v821 + 14) = v364;
            WORD3(v821[1]) = 2113;
            *(&v821[1] + 1) = v365;
            j___os_log_impl_1(
              &dword_180981000,
              v362,
              OS_LOG_TYPE_ERROR,
              "LAUNCH: No architectures specified in launch archictectures %{public}s for app=%{public}@ %{private}@ whic"
              "h likely is an error.",
              v821,
              0x20u);
            objc_release(v365);
            if ( SBYTE7(v820) < 0 )
              operator delete(v819);
            objc_release(v364);
          }
          objc_release(v362);
        }
LABEL_536:
        objc_release(v348);
        objc_release(v728);
        v366 = *(*(&v817 + 1) + 24LL);
        v345 = objc_retain(v349);
        if ( (_LSGetCPUType() & 0xFFFFFF) == 12 )
        {
          v367 = objc_retainAutoreleasedReturnValue(-[NSArray(MCXExtensions) firstObject](v345, "firstObject"));
          v368 = -[NSObject type](v367, "type");
          objc_release(v367);
          if ( v368 == 16777223 )
          {
            v369 = -[LSSliceInfo initWithType:subtype:](
                     objc_alloc(&OBJC_CLASS___LSSliceInfo),
                     "initWithType:subtype:",
                     16777223LL,
                     0xFFFFFFFFLL);
            *v822 = v369;
            v370 = objc_retainAutoreleasedReturnValue(+[NSArray arrayWithObjects:count:](&OBJC_CLASS___NSArray, "arrayWithObjects:count:", v822, 1LL));
            objc_release(v369);
            WouldBeSupportedIfCambriaWereInstalled = requestedArchitectureWouldBeSupportedIfCambriaWereInstalled(
                                                       v366,
                                                       v370);
            v372 = WouldBeSupportedIfCambriaWereInstalled;
            if ( WouldBeSupportedIfCambriaWereInstalled )
            {
              v373 = objc_retainAutoreleasedReturnValue(_LSOpenLog(WouldBeSupportedIfCambriaWereInstalled));
              if ( j__os_log_type_enabled_3(v373, OS_LOG_TYPE_ERROR) )
              {
                LOWORD(v835[0]) = 0;
                j___os_log_impl_1(
                  &dword_180981000,
                  v373,
                  OS_LOG_TYPE_ERROR,
                  "LAUNCH: User preference exists for x86_64 but runtime support is not installed.",
                  v835,
                  2u);
              }
              objc_release(v373);
              objc_release(v370);
              objc_release(v345);
              *(v800 + 6) = -10669;
              if ( (v372 & 1) != 0 )
                goto LABEL_498;
LABEL_545:
              v374 = j__mach_continuous_time_3();
              if ( !v161 )
                v161 = _LSAllocatePSN(4294967294LL, 0LL);
              v375 = objc_retainAutoreleasedReturnValue(getApplicationVersionString(*(*(&v817 + 1) + 24LL)));
              v708 = v374;
              v744 = objc_retain(v743);
              v376 = objc_retain(v375);
              v377 = objc_retain(v740);
              v724 = v376;
              v719 = v345;
              if ( v376 && -[LSBundleData length](v744, "length") && !_CSCheckFixWithInfo(CFSTR("9333942"), v744, v376) )
                objc_msgSend(
                  v377,
                  "setObject:forKeyedSubscript:",
                  &__kCFBooleanTrue,
                  CFSTR("LSLaunchModifierLaunchWithASLRDisabled"));
              if ( !_CSCheckFix(CFSTR("9315049")) )
                objc_msgSend(
                  v377,
                  "setObject:forKeyedSubscript:",
                  &__kCFBooleanTrue,
                  CFSTR("LSLaunchModifierLaunchWithASLRDisabled"));
              objc_release(v377);
              objc_release(v376);
              objc_release(v744);
              v378 = objc_retain(v736);
              v379 = objc_retain(v758);
              v380 = v379;
              if ( (v775 & 0x100200) == 0 )
              {
                if ( v378 )
                {
                  if ( isForegroundApplication(v379) )
                  {
                    v381 = -[NSString UTF8String](objc_retainAutorelease(v378), "UTF8String");
                    if ( v381 )
                    {
                      v382 = j__open_4(v381, 0);
                      v383 = v382;
                      if ( v382 >= 1 )
                      {
                        memset(v822, 0, 24);
                        j__fcntl_2(v382, 101, v822);
                        j__close_6(v383);
                      }
                    }
                  }
                }
              }
              objc_release(v380);
              objc_release(v378);
              v386 = *(*(&v817 + 1) + 24LL);
              if ( v386 )
              {
                v713 = 0;
                v726 = 0LL;
                v387 = v775 & 0x80000;
                if ( (v775 & 0x80000) == 0 && (*(v386 + 156) & 0x80) != 0 )
                {
                  v388 = objc_retainAutoreleasedReturnValue(_LSPlistGetValueForKey(
                                                              a1->db,
                                                              *(v386 + 120),
                                                              CFSTR("LSLaunchDLabel"),
                                                              v384));
                  v726 = v388;
                  if ( v388 )
                  {
                    v389 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v388));
                    if ( j__os_log_type_enabled_3(v389, OS_LOG_TYPE_INFO) )
                    {
                      *v822 = 138543875;
                      *&v822[4] = v726;
                      *&v822[12] = 2114;
                      *&v822[14] = v744;
                      *&v822[22] = 2113;
                      *&v822[24] = v748;
                      j___os_log_impl_1(
                        &dword_180981000,
                        v389,
                        OS_LOG_TYPE_INFO,
                        "LAUNCH: Launching via job label %{public}@, %{public}@ %{private}@",
                        v822,
                        0x20u);
                    }
                    objc_release(v389);
                    v721 = objc_retainAutoreleasedReturnValue(objc_msgSend(getRBSProcessIdentityClass(), "identityForDaemonJobLabel:", v726));
                    v713 = 1;
                    v387 = v721;
                    if ( v721 )
                    {
                      v709 = 0;
                      goto LABEL_572;
                    }
                  }
                  else
                  {
                    v390 = objc_retainAutoreleasedReturnValue(_LSOpenLog(0LL));
                    if ( j__os_log_type_enabled_3(v390, OS_LOG_TYPE_ERROR) )
                    {
                      *v822 = 138543619;
                      *&v822[4] = v744;
                      *&v822[12] = 2113;
                      *&v822[14] = v748;
                      j___os_log_impl_1(
                        &dword_180981000,
                        v390,
                        OS_LOG_TYPE_ERROR,
                        "LAUNCH: Can't determine application job label, so falling back to standard launch %{public}@ %{private}@",
                        v822,
                        0x16u);
                    }
                    objc_release(v390);
                    v387 = 0;
                    v726 = 0LL;
                    v713 = 0;
                  }
                }
              }
              else
              {
                v726 = 0LL;
                v713 = 0;
                v387 = v775 & 0x80000;
              }
              v721 = objc_retainAutoreleasedReturnValue(constructRBSIdentityFromBundleData(
                                                          *(*(&v817 + 1) + 24LL),
                                                          v744,
                                                          v748,
                                                          (v387 != 0),
                                                          v385));
              v709 = 1;
LABEL_572:
              v718 = objc_retainAutoreleasedReturnValue(constructEnvironmentDictionary(
                                                          a1,
                                                          *(*(&v817 + 1) + 24LL),
                                                          v744,
                                                          v724,
                                                          v765,
                                                          a9));
              v391 = objc_retain(v728);
              v392 = _LSGetCPUType();
              if ( (v392 & 0xFFFFFF) == 12 )
              {
                Shared = LaunchServices::PrefsStorage::GetShared(v392);
                *&v835[0] = 0LL;
                PointerKeysEnabledPreferenceForNode = LaunchServices::PrefsStorage::getPointerKeysEnabledPreferenceForNode(
                                                        Shared,
                                                        v391,
                                                        v835);
                v395 = objc_retain(*&v835[0]);
                v396 = v395;
                if ( PointerKeysEnabledPreferenceForNode <= 0xFFu )
                {
                  v397 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v395));
                  if ( j__os_log_type_enabled_3(v397, OS_LOG_TYPE_DEBUG) )
                  {
                    v398 = v391;
                    v399 = objc_retainAutoreleasedReturnValue(objc_msgSend(v391, "URL"));
                    *v822 = 138412546;
                    *&v822[4] = v399;
                    *&v822[12] = 2112;
                    *&v822[14] = v396;
                    j___os_log_impl_1(
                      &dword_180981000,
                      v397,
                      OS_LOG_TYPE_DEBUG,
                      "Could not check key state preference for node %@: %@",
                      v822,
                      0x16u);
                    objc_release(v399);
                    v391 = v398;
                  }
                  objc_release(v397);
                }
                if ( PointerKeysEnabledPreferenceForNode )
                  v400 = PointerKeysEnabledPreferenceForNode >= 0x100u;
                else
                  v400 = 0;
                v401 = !v400;
                objc_release(v396);
                v402 = v401;
              }
              else
              {
                v402 = 0;
              }
              objc_release(v391);
              v714 = objc_retainAutoreleasedReturnValue(
                       -[NSDictionary objectForKeyedSubscript:](
                         v380,
                         "objectForKeyedSubscript:",
                         CFSTR("LSLaunchedPersonaUID")));
              v712 = v377;
              if ( v794 )
              {
                v717 = objc_retain(objc_retainAutoreleasedReturnValue(objc_msgSend(v391, "pathWithError:", 0LL)));
                objc_release(v717);
              }
              else
              {
                v717 = 0LL;
              }
              v707 = v391;
              if ( v733 )
                v403 = 8;
              else
                v403 = 0;
              v404 = objc_retain(
                       objc_retainAutoreleasedReturnValue(
                         -[NSDictionary objectForKeyedSubscript:](
                           v380,
                           "objectForKeyedSubscript:",
                           CFSTR("ApplicationType"))));
              v405 = v404;
              v723 = objc_retain(v765);
              if ( v723 )
              {
                v406 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideBackgroundPriorityName](v723, "overrideBackgroundPriorityName"));
                v405 = v404;
                if ( v406 )
                {
LABEL_604:
                  if ( getRBSDomainAttributeClass(void)::sOnce != -1 )
                    j__dispatch_once_3(&getRBSDomainAttributeClass(void)::sOnce, &__block_literal_global_251_0);
                  v716 = objc_retainAutoreleasedReturnValue(
                           objc_msgSend(
                             objc_retainAutorelease(getRBSDomainAttributeClass(void)::sClassRBSDomainAttribute),
                             "attributeWithDomain:name:",
                             CFSTR("com.apple.launchservicesd"),
                             v406));
                  objc_release(v406);
LABEL_610:
                  objc_release(v723);
                  objc_release(v405);
                  objc_release(v404);
                  v410 = objc_retainAutoreleasedReturnValue(createSpawnConstraintsDictionary(
                                                              a1,
                                                              *(*(&v817 + 1) + 24LL),
                                                              v744,
                                                              v723));
                  v715 = v410;
                  v411 = v714;
                  if ( v714 )
                  {
                    v412 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v410));
                    if ( j__os_log_type_enabled_3(v412, OS_LOG_TYPE_DEBUG) )
                    {
                      LODWORD(v835[0]) = 0;
                      _LSASNExtractHighAndLowParts(v161, v835, 0LL);
                      v413 = v835[0];
                      LODWORD(v835[0]) = 0;
                      _LSASNExtractHighAndLowParts(v161, 0LL, v835);
                      *v822 = 67241219;
                      *&v822[4] = v413;
                      *&v822[8] = 1026;
                      *&v822[10] = v835[0];
                      *&v822[14] = 2114;
                      *&v822[16] = v744;
                      *&v822[24] = 2113;
                      *&v822[26] = v378;
                      *&v822[34] = 2114;
                      *&v822[36] = v714;
                      j___os_log_impl_1(
                        &dword_180981000,
                        v412,
                        OS_LOG_TYPE_DEBUG,
                        "LAUNCH: PERSONA: launching 0x%{public}x-0x%{public}x %{public}@ %{private}@ with persona %{public}@.",
                        v822,
                        0x2Cu);
                    }
                    objc_release(v412);
                  }
                  v414 = objc_retain(v380);
                  if ( v414 && v161 )
                  {
                    v415 = objc_retainAutoreleasedReturnValue(
                             +[NSDictionary dictionaryWithDictionary:](
                               &OBJC_CLASS___NSMutableDictionary,
                               "dictionaryWithDictionary:",
                               v414));
                    -[NSMutableDictionary setObject:forKeyedSubscript:](
                      v415,
                      "setObject:forKeyedSubscript:",
                      v161,
                      CFSTR("LSASN"));
                    _LSSendNotification(4294967294LL, 267LL, v415, 0LL, 0.0);
                    objc_release(v415);
                  }
                  v416 = (a6 != 0LL) | (v775 >> 12) & 1 | v710 | v722 | v711;
                  v417 = v403 | v416;
                  objc_release(v414);
                  v778 = 0LL;
                  v779 = 0LL;
                  v734 = objc_retainAutoreleasedReturnValue(launchThruRunningboard(
                                                              v721,
                                                              v378,
                                                              v717,
                                                              v744,
                                                              v161,
                                                              v750,
                                                              v718,
                                                              v719,
                                                              v723,
                                                              v714,
                                                              v417,
                                                              v716,
                                                              v715,
                                                              v402,
                                                              &v779,
                                                              &v778));
                  v720 = objc_retain(v779);
                  v418 = objc_retain(v778);
                  if ( !v418 )
                  {
                    v730 = 0LL;
                    v433 = 0LL;
LABEL_727:
                    objc_release(v772);
                    v772 = v433;
                    goto LABEL_728;
                  }
                  v729 = v418;
                  v419 = objc_retainAutoreleasedReturnValue(-[NSError domain](v418, "domain"));
                  v420 = -[NSString isEqual:](v419, "isEqual:", getRBSRequestErrorDomain());
                  objc_release(v419);
                  if ( v420 )
                  {
                    if ( v713 && -[NSError code](v729, "code") == 5 )
                    {
                      v421 = objc_retainAutoreleasedReturnValue(-[NSError userInfo](v729, "userInfo"));
                      v422 = objc_retainAutoreleasedReturnValue(
                               -[NSDictionary objectForKeyedSubscript:](
                                 v421,
                                 "objectForKeyedSubscript:",
                                 CFSTR("NSUnderlyingError")));
                      objc_release(v421);
                      if ( v422
                        && (v423 = objc_retainAutoreleasedReturnValue(objc_msgSend(v422, "domain")),
                            v424 = objc_msgSend(v423, "isEqual:", CFSTR("NSPOSIXErrorDomain")),
                            objc_release(v423),
                            v424)
                        && objc_msgSend(v422, "code") == 4 )
                      {
                        v425 = objc_retainAutoreleasedReturnValue(_LSOpenLog(4LL));
                        if ( j__os_log_type_enabled_3(v425, OS_LOG_TYPE_DEBUG) )
                        {
                          v426 = v402;
                          v427 = v378;
                          LODWORD(v835[0]) = 0;
                          _LSASNExtractHighAndLowParts(v161, v835, 0LL);
                          v428 = v835[0];
                          LODWORD(v835[0]) = 0;
                          _LSASNExtractHighAndLowParts(v161, 0LL, v835);
                          *v822 = 67240963;
                          *&v822[4] = v428;
                          *&v822[8] = 1026;
                          *&v822[10] = v835[0];
                          *&v822[14] = 2114;
                          *&v822[16] = v744;
                          *&v822[24] = 2113;
                          v378 = v427;
                          *&v822[26] = v427;
                          j___os_log_impl_1(
                            &dword_180981000,
                            v425,
                            OS_LOG_TYPE_DEBUG,
                            "LAUNCH: Retrying runningboard launch without job label, 0x%{public}x-0x%{public}x %{public}@ %{private}@",
                            v822,
                            0x22u);
                          v402 = v426;
                        }
                        objc_release(v425);
                        v430 = objc_retainAutoreleasedReturnValue(constructRBSIdentityFromBundleData(
                                                                    *(*(&v817 + 1) + 24LL),
                                                                    v744,
                                                                    v748,
                                                                    ((v775 >> 19) & 1),
                                                                    v429));
                        objc_release(v721);
                        objc_release(v729);
                        v776 = 0LL;
                        v777 = v720;
                        LOBYTE(v706) = v402;
                        v431 = objc_retainAutoreleasedReturnValue(launchThruRunningboard(
                                                                    v430,
                                                                    v378,
                                                                    v717,
                                                                    v744,
                                                                    v161,
                                                                    v750,
                                                                    v718,
                                                                    v719,
                                                                    v723,
                                                                    v714,
                                                                    v417,
                                                                    v716,
                                                                    v715,
                                                                    v706,
                                                                    &v777,
                                                                    &v776));
                        v432 = objc_retain(v777);
                        objc_release(v720);
                        v729 = objc_retain(v776);
                        objc_release(v734);
                        LOBYTE(v713) = 0;
                        v709 = 1;
                        v720 = v432;
                        v721 = v430;
                        v734 = v431;
                      }
                      else
                      {
                        LOBYTE(v713) = 1;
                      }
                      objc_release(v422);
                      v456 = objc_retain(v729);
                      objc_release(v772);
                      if ( !v456 )
                      {
                        v730 = 0LL;
                        v772 = 0LL;
                        goto LABEL_728;
                      }
                      v435 = v456;
LABEL_631:
                      v730 = v435;
                      v436 = objc_retainAutoreleasedReturnValue(-[NSError userInfo](v435, "userInfo"));
                      v437 = objc_retainAutoreleasedReturnValue(-[NSDictionary objectForKey:](v436, "objectForKey:", CFSTR("NSUnderlyingError")));
                      objc_release(v436);
                      v438 = objc_retainAutoreleasedReturnValue(objc_msgSend(v437, "domain"));
                      if ( objc_msgSend(v438, "isEqual:", CFSTR("NSPOSIXErrorDomain"))
                        && objc_msgSend(v437, "code") == 80 )
                      {
                        v439 = objc_retainAutoreleasedReturnValue(-[NSError domain](v730, "domain"));
                        v440 = -[NSString isEqual:](v439, "isEqual:", getRBSRequestErrorDomain());
                        objc_release(v439);
                        objc_release(v438);
                        if ( v440 )
                        {
                          *(v800 + 6) = -10671;
                          v772 = v730;
                          v411 = v714;
                          goto LABEL_722;
                        }
                      }
                      else
                      {
                        objc_release(v438);
                      }
                      v411 = v714;
                      v441 = objc_retainAutoreleasedReturnValue(-[NSError domain](v730, "domain"));
                      v442 = -[NSString isEqual:](v441, "isEqual:", getRBSRequestErrorDomain());
                      objc_release(v441);
                      if ( v442 )
                      {
                        v443 = -[NSError code](v730, "code");
                        switch ( v443 )
                        {
                          case 0LL:
                            v444 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v443));
                            if ( !j__os_log_type_enabled_3(v444, OS_LOG_TYPE_DEBUG) )
                              goto LABEL_714;
                            *v822 = 138543875;
                            *&v822[4] = v744;
                            *&v822[12] = 2113;
                            *&v822[14] = v748;
                            *&v822[22] = 2114;
                            *&v822[24] = v730;
                            v445 = "LAUNCH: Runningboard informed us that the launch of %{public}@ %{private}@ was succes"
                                   "sful but returned RBSRequestErrorNone, so ignoring error %{public}@.";
                            v446 = v444;
                            v447 = 32;
                            goto LABEL_713;
                          case 1LL:
                            v491 = objc_retainAutoreleasedReturnValue(
                                     +[NSDictionary dictionaryWithObjectsAndKeys:](
                                       &OBJC_CLASS___NSDictionary,
                                       "dictionaryWithObjectsAndKeys:",
                                       v730,
                                       CFSTR("NSUnderlyingError"),
                                       0LL));
                            v772 = objc_retainAutoreleasedReturnValue(
                                     +[NSError errorWithDomain:code:userInfo:](
                                       &OBJC_CLASS___NSError,
                                       "errorWithDomain:code:userInfo:",
                                       CFSTR("NSOSStatusErrorDomain"),
                                       -50LL,
                                       v491));
                            objc_release(v730);
                            objc_release(v491);
                            *(v800 + 6) = -50;
                            v493 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v492));
                            if ( j__os_log_type_enabled_3(v493, OS_LOG_TYPE_ERROR) )
                            {
                              v494 = *(v800 + 6);
                              *v822 = 138544131;
                              *&v822[4] = v744;
                              *&v822[12] = 2113;
                              *&v822[14] = v748;
                              *&v822[22] = 2114;
                              *&v822[24] = v772;
                              *&v822[32] = 1026;
                              *&v822[34] = v494;
                              j___os_log_impl_1(
                                &dword_180981000,
                                v493,
                                OS_LOG_TYPE_ERROR,
                                "LAUNCH: Runningboard launch of %{public}@ %{private}@ returned RBSRequestErrorInvalidPar"
                                "ameters, error %{public}@, so returning paramErr/%{public}d",
                                v822,
                                0x26u);
                            }
                            objc_release(v493);
                            goto LABEL_722;
                          case 2LL:
                            v444 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v443));
                            if ( j__os_log_type_enabled_3(v444, OS_LOG_TYPE_DEBUG) )
                            {
                              *v822 = 138543619;
                              *&v822[4] = v744;
                              *&v822[12] = 2113;
                              *&v822[14] = v748;
                              v445 = "LAUNCH: Runningboard informed us that the launch of %{public}@ %{private}@ was unne"
                                     "cessary, as it is already running.";
                              v446 = v444;
                              v447 = 22;
LABEL_713:
                              j___os_log_impl_1(&dword_180981000, v446, OS_LOG_TYPE_DEBUG, v445, v822, v447);
                            }
LABEL_714:
                            objc_release(v444);
                            *(v800 + 6) = 0;
                            objc_release(v730);
                            v772 = 0LL;
                            goto LABEL_722;
                          case 3LL:
                            *(v800 + 6) = -10810;
                            objc_release(v734);
                            v486 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v497));
                            if ( j__os_log_type_enabled_3(v486, OS_LOG_TYPE_ERROR) )
                              goto LABEL_703;
                            goto LABEL_720;
                          case 4LL:
                            *(v800 + 6) = -10826;
                            objc_release(v734);
                            v486 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v498));
                            if ( !j__os_log_type_enabled_3(v486, OS_LOG_TYPE_ERROR) )
                              goto LABEL_720;
                            v499 = *(v800 + 6);
                            *v822 = 138544131;
                            *&v822[4] = v744;
                            *&v822[12] = 2113;
                            *&v822[14] = v748;
                            *&v822[22] = 2114;
                            *&v822[24] = v730;
                            *&v822[32] = 1026;
                            *&v822[34] = v499;
                            v488 = "LAUNCH: Runningboard launch of %{public}@ %{private}@ returned RBSRequestErrorDenied,"
                                   " error %{public}@, so returning %{public}d";
                            goto LABEL_719;
                          case 5LL:
                            *(v800 + 6) = -10810;
                            objc_release(v734);
                            v486 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v489));
                            if ( !j__os_log_type_enabled_3(v486, OS_LOG_TYPE_ERROR) )
                              goto LABEL_720;
                            v490 = *(v800 + 6);
                            *v822 = 138544131;
                            *&v822[4] = v744;
                            *&v822[12] = 2113;
                            *&v822[14] = v748;
                            *&v822[22] = 2114;
                            *&v822[24] = v730;
                            *&v822[32] = 1026;
                            *&v822[34] = v490;
                            v488 = "LAUNCH: Runningboard launch of %{public}@ %{private}@ returned RBSRequestErrorFailed,"
                                   " error %{public}@, so returning %{public}d";
                            goto LABEL_719;
                          case 7LL:
                            *(v800 + 6) = -10699;
                            objc_release(v734);
                            v486 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v495));
                            if ( !j__os_log_type_enabled_3(v486, OS_LOG_TYPE_ERROR) )
                              goto LABEL_720;
                            v496 = *(v800 + 6);
                            *v822 = 138544131;
                            *&v822[4] = v744;
                            *&v822[12] = 2113;
                            *&v822[14] = v748;
                            *&v822[22] = 2114;
                            *&v822[24] = v730;
                            *&v822[32] = 1026;
                            *&v822[34] = v496;
                            v488 = "LAUNCH: Runningboard launch of %{public}@ %{private}@ returned RBSRequestErrorLaunchP"
                                   "revented, error %{public}@, so returning %{public}d";
                            goto LABEL_719;
                          default:
                            *(v800 + 6) = -10810;
                            objc_release(v734);
                            v486 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v485));
                            if ( !j__os_log_type_enabled_3(v486, OS_LOG_TYPE_ERROR) )
                              goto LABEL_720;
LABEL_703:
                            v487 = *(v800 + 6);
                            *v822 = 138544131;
                            *&v822[4] = v744;
                            *&v822[12] = 2113;
                            *&v822[14] = v748;
                            *&v822[22] = 2114;
                            *&v822[24] = v730;
                            *&v822[32] = 1026;
                            *&v822[34] = v487;
                            v488 = "LAUNCH: Runningboard launch of %{public}@ %{private}@ returned unexpected value, erro"
                                   "r %{public}@, so returning %{public}d";
LABEL_719:
                            j___os_log_impl_1(&dword_180981000, v486, OS_LOG_TYPE_ERROR, v488, v822, 0x26u);
LABEL_720:
                            objc_release(v486);
                            v734 = 0LL;
                            break;
                        }
                        goto LABEL_721;
                      }
                      v448 = objc_retainAutoreleasedReturnValue(-[NSError domain](v730, "domain"));
                      v449 = -[NSString isEqual:](v448, "isEqual:", CFSTR("NSPOSIXErrorDomain"));
                      objc_release(v448);
                      if ( v449 )
                      {
                        v451 = _LSGetOSStatusFromPOSIXErrorCode(-[NSError code](v730, "code"));
                        *(v800 + 6) = v451;
                        v452 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v451));
                        if ( j__os_log_type_enabled_3(v452, OS_LOG_TYPE_ERROR) )
                        {
                          v453 = *(v800 + 6);
                          *v822 = 138544131;
                          *&v822[4] = v744;
                          *&v822[12] = 2113;
                          *&v822[14] = v748;
                          *&v822[22] = 2114;
                          *&v822[24] = v730;
                          *&v822[32] = 1026;
                          *&v822[34] = v453;
                          v454 = "LAUNCH: Runningboard launch of %{public}@ %{private}@ returned unexpected POSIX error %"
                                 "{public}@, returning %{public}d";
LABEL_645:
                          j___os_log_impl_1(&dword_180981000, v452, OS_LOG_TYPE_ERROR, v454, v822, 0x26u);
                        }
                      }
                      else
                      {
                        *(v800 + 6) = -10810;
                        v452 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v450));
                        if ( j__os_log_type_enabled_3(v452, OS_LOG_TYPE_ERROR) )
                        {
                          v455 = *(v800 + 6);
                          *v822 = 138544131;
                          *&v822[4] = v744;
                          *&v822[12] = 2113;
                          *&v822[14] = v748;
                          *&v822[22] = 2114;
                          *&v822[24] = v730;
                          *&v822[32] = 1026;
                          *&v822[34] = v455;
                          v454 = "LAUNCH: Runningboard launch of %{public}@ %{private}@ returned unexpected error %{publi"
                                 "c}@, returning kLSUnknownErr/%{public}d.";
                          goto LABEL_645;
                        }
                      }
                      objc_release(v452);
LABEL_721:
                      v772 = v730;
LABEL_722:
                      objc_release(v437);
                      if ( !*(v800 + 6)
                        || (v457 = v772) == 0
                        || (v457 = _LSGetOSStatusFromNSError(v772), v500 = *(v800 + 6), v457 == v500) )
                      {
LABEL_728:
                        if ( !v734 )
                        {
                          v513 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v457));
                          if ( j__os_log_type_enabled_3(v513, OS_LOG_TYPE_ERROR) )
                          {
                            LODWORD(v835[0]) = 0;
                            _LSASNExtractHighAndLowParts(v161, v835, 0LL);
                            v514 = v835[0];
                            LODWORD(v835[0]) = 0;
                            _LSASNExtractHighAndLowParts(v161, 0LL, v835);
                            *v822 = 67241219;
                            *&v822[4] = v514;
                            *&v822[8] = 1026;
                            *&v822[10] = v835[0];
                            *&v822[14] = 2114;
                            *&v822[16] = v744;
                            *&v822[24] = 2113;
                            *&v822[26] = v748;
                            *&v822[34] = 2114;
                            *&v822[36] = v772;
                            j___os_log_impl_1(
                              &dword_180981000,
                              v513,
                              OS_LOG_TYPE_ERROR,
                              "LAUNCH: request execute thru runningboard of 0x%{public}x-0x%{public}x %{public}@/%{privat"
                              "e}@ failed with error=%{public}@",
                              v822,
                              0x2Cu);
                          }
                          objc_release(v513);
                          if ( !*(v800 + 6) )
                          {
                            *(v800 + 6) = -10810;
                            v516 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v515));
                            if ( j__os_log_type_enabled_3(v516, OS_LOG_TYPE_ERROR) )
                            {
                              v517 = *(v800 + 6);
                              LODWORD(v835[0]) = 0;
                              _LSASNExtractHighAndLowParts(v161, v835, 0LL);
                              v518 = v835[0];
                              LODWORD(v835[0]) = 0;
                              _LSASNExtractHighAndLowParts(v161, 0LL, v835);
                              *v822 = 67241475;
                              *&v822[4] = v517;
                              *&v822[8] = 1026;
                              *&v822[10] = v518;
                              *&v822[14] = 1026;
                              *&v822[16] = v835[0];
                              *&v822[20] = 2114;
                              *&v822[22] = v744;
                              *&v822[30] = 2113;
                              *&v822[32] = v748;
                              *&v822[40] = 2114;
                              *&v822[42] = v772;
                              j___os_log_impl_1(
                                &dword_180981000,
                                v516,
                                OS_LOG_TYPE_ERROR,
                                "LAUNCH: Returning kLSUnknownErr/%{public}d for 0x%{public}x-0x%{public}x %{public}@/%{pr"
                                "ivate}@ failed with error=%{public}@",
                                v822,
                                0x32u);
                            }
                            objc_release(v516);
                          }
                          v248 = 0LL;
                          v519 = 0LL;
                          goto LABEL_816;
                        }
                        v503 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v457));
                        if ( j__os_log_type_enabled_3(v503, OS_LOG_TYPE_INFO) )
                        {
                          LODWORD(v835[0]) = 0;
                          _LSASNExtractHighAndLowParts(v161, v835, 0LL);
                          v504 = v835[0];
                          LODWORD(v835[0]) = 0;
                          _LSASNExtractHighAndLowParts(v161, 0LL, v835);
                          v505 = v835[0];
                          v506 = objc_msgSend(v734, "pid");
                          v507 = v744;
                          if ( (v713 & (v726 != 0LL)) == 1 )
                            v507 = objc_retainAutoreleasedReturnValue(
                                     +[NSString stringWithFormat:](
                                       &OBJC_CLASS___NSString,
                                       "stringWithFormat:",
                                       CFSTR("label:%@"),
                                       v726));
                          v508 = CFSTR("(quarantined) ");
                          *v822 = 67241475;
                          *&v822[4] = v504;
                          *&v822[8] = 1026;
                          *&v822[10] = v505;
                          if ( (v775 & 0x2000000) == 0 )
                            v508 = &stru_1ED1C6B98;
                          *&v822[14] = 1024;
                          *&v822[16] = v506;
                          *&v822[20] = 2114;
                          *&v822[22] = v507;
                          *&v822[30] = 2114;
                          *&v822[32] = v508;
                          *&v822[40] = 2113;
                          *&v822[42] = v748;
                          j___os_log_impl_1(
                            &dword_180981000,
                            v503,
                            OS_LOG_TYPE_INFO,
                            "LAUNCH: Successful launched 0x%{public}x-0x%{public}x pid=%d %{public}@ %{public}@ '%{private}@'",
                            v822,
                            0x32u);
                          if ( (v713 & (v726 != 0LL)) != 0 )
                            objc_release(v507);
                        }
                        objc_release(v503);
                        if ( off_1ED1E6990[0] )
                        {
                          v509 = isForegroundApplication(v414);
                          v510 = objc_retainAutoreleasedReturnValue(getApplicationVersionString(*(*(&v817 + 1) + 24LL)));
                          v511 = v510;
                          if ( v510 )
                            v512 = objc_msgSend(objc_retainAutorelease(v510), "cStringUsingEncoding:", 4LL);
                          else
                            v512 = 0LL;
                          alm_app_will_launch_with_signpost_id(
                            "runningboardd",
                            !(((v775 & 0x100200) == 0) & v509),
                            v512,
                            v512,
                            v708,
                            objc_msgSend(v734, "pid"));
                          objc_release(v511);
                        }
                        -[NSDictionary setObject:forKeyedSubscript:](
                          v414,
                          "setObject:forKeyedSubscript:",
                          &__kCFBooleanTrue,
                          CFSTR("LSLaunchedByLaunchServices"));
                        v161 = objc_retain(v161);
                        -[NSDictionary setObject:forKeyedSubscript:](
                          v414,
                          "setObject:forKeyedSubscript:",
                          v161,
                          CFSTR("LSASN"));
                        objc_release(v161);
                        v520 = objc_retainAutoreleasedReturnValue(
                                 +[NSNumber numberWithLong:](
                                   &OBJC_CLASS___NSNumber,
                                   "numberWithLong:",
                                   objc_msgSend(v734, "pid")));
                        -[NSDictionary setObject:forKeyedSubscript:](
                          v414,
                          "setObject:forKeyedSubscript:",
                          v520,
                          CFSTR("pid"));
                        objc_release(v520);
                        memset(v835, 0, sizeof(v835));
                        objc_msgSend_auditToken(v835, v734, v521);
                        v522 = objc_retainAutoreleasedReturnValue(
                                 +[NSData dataWithBytes:length:](
                                   &OBJC_CLASS___NSData,
                                   "dataWithBytes:length:",
                                   v835,
                                   32LL));
                        -[NSDictionary setObject:forKeyedSubscript:](
                          v414,
                          "setObject:forKeyedSubscript:",
                          v522,
                          CFSTR("LSAuditToken"));
                        objc_release(v522);
                        -[NSDictionary setObject:forKeyedSubscript:](
                          v414,
                          "setObject:forKeyedSubscript:",
                          _LSGetCurrentApplicationASN(),
                          CFSTR("LSParentASN"));
                        v523 = objc_retainAutoreleasedReturnValue(
                                 +[NSNumber numberWithUnsignedLongLong:](
                                   &OBJC_CLASS___NSNumber,
                                   "numberWithUnsignedLongLong:",
                                   CGSCurrentEventTimestamp(
                                     -[NSDictionary setObject:forKeyedSubscript:](
                                       v414,
                                       "setObject:forKeyedSubscript:",
                                       v756,
                                       CFSTR("LSLaunchTime")))));
                        -[NSDictionary setObject:forKeyedSubscript:](
                          v414,
                          "setObject:forKeyedSubscript:",
                          v523,
                          CFSTR("LSLaunchEventRecordTime"));
                        objc_release(v523);
                        -[NSDictionary setObject:forKeyedSubscript:](
                          v414,
                          "setObject:forKeyedSubscript:",
                          &__kCFBooleanTrue,
                          CFSTR("LSLaunchedWithLaunchD"));
                        v524 = objc_retainAutoreleasedReturnValue(objc_msgSend(v712, "objectForKeyedSubscript:", CFSTR("LSLaunchRefCon")));
                        if ( v524 )
                          -[NSDictionary setObject:forKeyedSubscript:](
                            v414,
                            "setObject:forKeyedSubscript:",
                            v524,
                            CFSTR("LSLaunchRefCon"));
                        objc_release(v524);
                        if ( (v713 & (v726 != 0LL)) == 1 )
                          -[NSDictionary setObject:forKeyedSubscript:](
                            v414,
                            "setObject:forKeyedSubscript:",
                            v726,
                            CFSTR("LSLaunchDLabel"));
                        if ( (v775 & 0x2000000) != 0 )
                        {
                          -[NSDictionary setObject:forKeyedSubscript:](
                            v414,
                            "setObject:forKeyedSubscript:",
                            &__kCFBooleanTrue,
                            CFSTR("LSLaunchedInQuarantine"));
                          -[NSDictionary setObject:forKeyedSubscript:](
                            v414,
                            "setObject:forKeyedSubscript:",
                            &__kCFBooleanTrue,
                            CFSTR("LSApplicationLockedInStoppedStateKey"));
                        }
                        if ( v416 )
                          -[NSDictionary setObject:forKeyedSubscript:](
                            v414,
                            "setObject:forKeyedSubscript:",
                            &__kCFBooleanTrue,
                            CFSTR("LSStoppedState"));
                        v525 = objc_retainAutoreleasedReturnValue(
                                 -[NSDictionary objectForKeyedSubscript:](
                                   v414,
                                   "objectForKeyedSubscript:",
                                   CFSTR("LSDisplayName")));
                        objc_release(v525);
                        if ( !v525 )
                        {
                          v526 = objc_retainAutoreleasedReturnValue(
                                   +[_LSDisplayNameConstructor displayNameConstructorWithContext:bundle:bundleClass:node:preferredLocalizations:error:](
                                     &OBJC_CLASS____LSDisplayNameConstructor,
                                     "displayNameConstructorWithContext:bundle:bundleClass:node:preferredLocalizations:error:",
                                     a1,
                                     *(v796 + 6),
                                     0LL,
                                     v707,
                                     0LL,
                                     0LL));
                          v527 = v526;
                          if ( v526 )
                          {
                            v528 = objc_retainAutoreleasedReturnValue(
                                     -[_LSDisplayNameConstructor unlocalizedNameWithContext:asIfShowingAllExtensions:](
                                       v526,
                                       "unlocalizedNameWithContext:asIfShowingAllExtensions:",
                                       a1,
                                       &__kCFBooleanFalse));
                            if ( v528 )
                              goto LABEL_763;
                          }
                          v529 = *(*(&v817 + 1) + 24LL);
                          if ( v529 )
                          {
                            v530 = *(v529 + 108);
                            if ( v530 )
                            {
                              v528 = objc_retainAutoreleasedReturnValue(_LSDatabaseGetNSStringFromString(a1->db, v530));
                              if ( v528 )
                                goto LABEL_763;
                            }
                          }
                          v531 = objc_retainAutoreleasedReturnValue(
                                   -[NSDictionary objectForKeyedSubscript:](
                                     v414,
                                     "objectForKeyedSubscript:",
                                     CFSTR("LSBundlePath")));
                          v532 = objc_retainAutoreleasedReturnValue(
                                   -[NSDictionary objectForKeyedSubscript:](
                                     v414,
                                     "objectForKeyedSubscript:",
                                     CFSTR("CFBundleExecutablePath")));
                          v528 = CopyAndConstructAppropriateDisplayName(v531, v532);
                          objc_release(v532);
                          objc_release(v531);
                          if ( v528 )
LABEL_763:
                            -[NSDictionary setObject:forKeyedSubscript:](
                              v414,
                              "setObject:forKeyedSubscript:",
                              v528,
                              CFSTR("LSDisplayName"));
                          objc_release(v527);
                          objc_release(v528);
                          v411 = v714;
                        }
                        if ( a4 )
                        {
                          v533 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithLong:](&OBJC_CLASS___NSNumber, "numberWithLong:", a4));
                          -[NSDictionary setObject:forKeyedSubscript:](
                            v414,
                            "setObject:forKeyedSubscript:",
                            v533,
                            CFSTR("LSLaunchRefCon"));
                          objc_release(v533);
                        }
                        *&v821[0] = 0LL;
                        v534 = objc_msgSend(v734, "pid");
                        v535 = *&v821[0];
                        *&v821[0] = 0LL;
                        if ( v535 )
                          j__CFRelease(v535);
                        v536 = _CASNotifyServerSideAboutLaunchedApplication(
                                 4294967294LL,
                                 v414,
                                 0LL,
                                 v712,
                                 v534,
                                 v709,
                                 v821);
                        *(v800 + 6) = v536;
                        if ( !v536 || v536 == -13052 )
                        {
                          v537 = *&v821[0];
                          v538 = _LSASNGetTypeID();
                          if ( CFSTR("LSASN") && v537 )
                          {
                            v539 = v538;
                            v540 = j__CFDictionaryGetValue(v537, CFSTR("LSASN"));
                            v541 = v540;
                            if ( v539 && v540 && j__CFGetTypeID(v540) != v539 )
                              v541 = 0LL;
                            if ( v541 )
                            {
                              v542 = *&v821[0];
                              if ( *&v821[0] )
                              {
                                v543 = objc_retainAutoreleasedReturnValue(getLocallyLaunchedApplicationsDispatchQ());
                                *v822 = &OBJC_CLASS_____NSStackBlock__;
                                *&v822[8] = 3221225472LL;
                                *&v822[16] = ___ZL32addToLocallyLaunchedApplicationsPK7__LSASNPK14__CFDictionary_block_invoke;
                                *&v822[24] = &__block_descriptor_48_e5_v8__0l_0;
                                *&v822[32] = v541;
                                *&v822[40] = v542;
                                j__dispatch_sync_1(v543, v822);
                                objc_release(v543);
                              }
                            }
                          }
                          v536 = *(v800 + 6);
                        }
                        if ( v536 == -13052 )
                        {
                          v547 = CFDictionaryCopyValueAsLSASN(*&v821[0], CFSTR("LSASN"));
                          v548 = v547;
                          if ( v161 )
                            j__CFRelease(v161);
                          v549 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v547));
                          if ( j__os_log_type_enabled_3(v549, OS_LOG_TYPE_INFO) )
                          {
                            v550 = objc_msgSend(v734, "pid");
                            v551 = _LSASNToUInt64(v548);
                            v552 = _LSASNToUInt64(v548);
                            *v822 = 67110147;
                            *&v822[4] = v550;
                            *&v822[8] = 2048;
                            *&v822[10] = HIDWORD(v551);
                            *&v822[18] = 2048;
                            *&v822[20] = v552;
                            *&v822[28] = 2114;
                            *&v822[30] = v744;
                            *&v822[38] = 2113;
                            *&v822[40] = v748;
                            j___os_log_impl_1(
                              &dword_180981000,
                              v549,
                              OS_LOG_TYPE_INFO,
                              "LAUNCH: An application for this pid %d is already running, 0x%llx-0x%llx %{public}@ %{private}@",
                              v822,
                              0x30u);
                          }
                          objc_release(v549);
                          v248 = 0LL;
                          *(v800 + 6) = -10652;
                          v161 = v548;
                          goto LABEL_813;
                        }
                        if ( !v536 )
                        {
                          v544 = objc_retainAutoreleasedReturnValue(
                                   -[NSDictionary objectForKeyedSubscript:](
                                     v414,
                                     "objectForKeyedSubscript:",
                                     CFSTR("LSDisplayName")));
                          v545 = *(*(&v817 + 1) + 24LL);
                          if ( v545 )
                            v546 = *(v545 + 180);
                          else
                            v546 = 0;
                          hintAppleEventsAndSendInitialAppleEvent(
                            v744,
                            v544,
                            v546,
                            v161,
                            objc_msgSend(v734, "pid"),
                            a6,
                            a7,
                            a11,
                            v775,
                            v723);
                          objc_release(v544);
                          v536 = *(v800 + 6);
                        }
                        v248 = 0LL;
                        if ( !v536 && v794 )
                        {
                          v553 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v536));
                          if ( j__os_log_type_enabled_3(v553, OS_LOG_TYPE_INFO) )
                          {
                            LODWORD(v819) = 0;
                            _LSASNExtractHighAndLowParts(v161, &v819, 0LL);
                            v554 = v819;
                            LODWORD(v819) = 0;
                            _LSASNExtractHighAndLowParts(v161, 0LL, &v819);
                            v555 = v819;
                            v556 = objc_msgSend(v734, "pid");
                            *v822 = 67241219;
                            *&v822[4] = v554;
                            *&v822[8] = 1026;
                            *&v822[10] = v555;
                            *&v822[14] = 2114;
                            *&v822[16] = v744;
                            *&v822[24] = 2113;
                            *&v822[26] = v748;
                            *&v822[34] = 1026;
                            *&v822[36] = v556;
                            j___os_log_impl_1(
                              &dword_180981000,
                              v553,
                              OS_LOG_TYPE_INFO,
                              "LAUNCH: Launched translocated app 0x%{public}x-0x%{public}x %{public}@/%{private}@, so che"
                              "cking it in with pid %{public}d.",
                              v822,
                              0x28u);
                          }
                          objc_release(v553);
                          _LSTranslocateAppLaunchCheckIn(objc_msgSend(v734, "pid"));
                          v536 = *(v800 + 6);
                          v248 = 1LL;
                        }
                        if ( v536 )
                          goto LABEL_813;
                        if ( (v775 & 0x2000000) != 0 )
                        {
                          v563 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v536));
                          if ( !j__os_log_type_enabled_3(v563, OS_LOG_TYPE_INFO) )
                            goto LABEL_812;
                          LODWORD(v819) = 0;
                          _LSASNExtractHighAndLowParts(v161, &v819, 0LL);
                          v568 = v819;
                          LODWORD(v819) = 0;
                          _LSASNExtractHighAndLowParts(v161, 0LL, &v819);
                          *v822 = 67240706;
                          *&v822[4] = v568;
                          *&v822[8] = 1026;
                          *&v822[10] = v819;
                          *&v822[14] = 2114;
                          *&v822[16] = v744;
                          v565 = "LAUNCH: 0x%{public}x-0x%{public}x %{public}@ launched with launchInQuarantine == true, "
                                 "so not starting the application.";
                        }
                        else
                        {
                          if ( (v775 & 0x1000) == 0 )
                          {
                            if ( !v722 )
                            {
                              if ( ((a6 == 0LL) & (v711 ^ 1)) == 0 )
                              {
                                v668 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v536));
                                if ( j__os_log_type_enabled_3(v668, OS_LOG_TYPE_INFO) )
                                {
                                  LODWORD(v819) = 0;
                                  _LSASNExtractHighAndLowParts(v161, &v819, 0LL);
                                  v669 = v819;
                                  LODWORD(v819) = 0;
                                  _LSASNExtractHighAndLowParts(v161, 0LL, &v819);
                                  v670 = v819;
                                  v671 = objc_msgSend(v734, "pid");
                                  *v822 = 67240962;
                                  *&v822[4] = v669;
                                  *&v822[8] = 1026;
                                  *&v822[10] = v670;
                                  *&v822[14] = 2114;
                                  *&v822[16] = v744;
                                  *&v822[24] = 1026;
                                  *&v822[26] = v671;
                                  j___os_log_impl_1(
                                    &dword_180981000,
                                    v668,
                                    OS_LOG_TYPE_INFO,
                                    "LAUNCH: Application 0x%{public}x-0x%{public}x %{public}@ launched with pid %{public}"
                                    "d, starting the application.",
                                    v822,
                                    0x1Eu);
                                }
                                objc_release(v668);
                                startApplicationIfNecessary(v161, v744);
                              }
                              goto LABEL_813;
                            }
                            v557 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v536));
                            if ( j__os_log_type_enabled_3(v557, OS_LOG_TYPE_INFO) )
                            {
                              LODWORD(v819) = 0;
                              _LSASNExtractHighAndLowParts(v161, &v819, 0LL);
                              v558 = v819;
                              LODWORD(v819) = 0;
                              _LSASNExtractHighAndLowParts(v161, 0LL, &v819);
                              v559 = v819;
                              v560 = objc_msgSend(v734, "pid");
                              *v822 = 67240962;
                              *&v822[4] = v558;
                              *&v822[8] = 1026;
                              *&v822[10] = v559;
                              *&v822[14] = 2114;
                              *&v822[16] = v744;
                              *&v822[24] = 1026;
                              *&v822[26] = v560;
                              j___os_log_impl_1(
                                &dword_180981000,
                                v557,
                                OS_LOG_TYPE_INFO,
                                "LAUNCH: Application 0x%{public}x-0x%{public}x %{public}@ launched with pid %{public}d, w"
                                "as a beta app; sending ping to CSUIA.",
                                v822,
                                0x1Eu);
                            }
                            objc_release(v557);
                            v562 = informCSUIAOfStoppedBetaAppLaunch(v161, v561);
                            if ( (v562 & 1) == 0 )
                            {
                              v563 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v562));
                              if ( j__os_log_type_enabled_3(v563, OS_LOG_TYPE_ERROR) )
                              {
                                LODWORD(v819) = 0;
                                _LSASNExtractHighAndLowParts(v161, &v819, 0LL);
                                v564 = v819;
                                LODWORD(v819) = 0;
                                _LSASNExtractHighAndLowParts(v161, 0LL, &v819);
                                *v822 = 67240706;
                                *&v822[4] = v564;
                                *&v822[8] = 1026;
                                *&v822[10] = v819;
                                *&v822[14] = 2114;
                                *&v822[16] = v744;
                                v565 = "LAUNCH: Could not ping CSUIA for suspended beta app 0x%{public}x-0x%{public}x %{public}@!";
                                v566 = v563;
                                v567 = OS_LOG_TYPE_ERROR;
LABEL_811:
                                j___os_log_impl_1(&dword_180981000, v566, v567, v565, v822, 0x18u);
                              }
LABEL_812:
                              objc_release(v563);
                            }
LABEL_813:
                            if ( *&v821[0] )
                              j__CFRelease(*&v821[0]);
                            v519 = objc_msgSend(v734, "pid");
LABEL_816:
                            v570 = objc_retain(v414);
                            if ( v414 && v161 )
                            {
                              v571 = objc_retainAutoreleasedReturnValue(
                                       +[NSDictionary dictionaryWithDictionary:](
                                         &OBJC_CLASS___NSMutableDictionary,
                                         "dictionaryWithDictionary:",
                                         v570));
                              -[NSMutableDictionary setObject:forKeyedSubscript:](
                                v571,
                                "setObject:forKeyedSubscript:",
                                v161,
                                CFSTR("LSASN"));
                              if ( v519 )
                              {
                                v572 = objc_retainAutoreleasedReturnValue(+[NSNumber numberWithInt:](&OBJC_CLASS___NSNumber, "numberWithInt:", v519));
                                -[NSMutableDictionary setObject:forKeyedSubscript:](
                                  v571,
                                  "setObject:forKeyedSubscript:",
                                  v572,
                                  CFSTR("pid"));
                                objc_release(v572);
                              }
                              _LSSendNotification(4294967294LL, 268LL, v571, 0LL, 0.0);
                              objc_release(v571);
                            }
                            objc_release(v570);
                            objc_msgSend(v720, "invalidate");
                            objc_release(v734);
                            objc_release(v730);
                            objc_release(v715);
                            objc_release(v716);
                            objc_release(v717);
                            objc_release(v411);
                            objc_release(v718);
                            objc_release(v726);
                            objc_release(v721);
                            objc_release(v724);
                            objc_release(v720);
                            v345 = v719;
                            goto LABEL_822;
                          }
                          v563 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v536));
                          if ( !j__os_log_type_enabled_3(v563, OS_LOG_TYPE_INFO) )
                            goto LABEL_812;
                          LODWORD(v819) = 0;
                          _LSASNExtractHighAndLowParts(v161, &v819, 0LL);
                          v569 = v819;
                          LODWORD(v819) = 0;
                          _LSASNExtractHighAndLowParts(v161, 0LL, &v819);
                          *v822 = 67240706;
                          *&v822[4] = v569;
                          *&v822[8] = 1026;
                          *&v822[10] = v819;
                          *&v822[14] = 2114;
                          *&v822[16] = v744;
                          v565 = "LAUNCH: 0x%{public}x-0x%{public}x %{public}@ launched with launchInStoppedState=true, a"
                                 "nd not starting the application.";
                        }
                        v566 = v563;
                        v567 = OS_LOG_TYPE_INFO;
                        goto LABEL_811;
                      }
                      v807 = CFSTR("NSUnderlyingError");
                      v808 = v772;
                      v501 = objc_retainAutoreleasedReturnValue(
                               +[NSDictionary dictionaryWithObjects:forKeys:count:](
                                 &OBJC_CLASS___NSDictionary,
                                 "dictionaryWithObjects:forKeys:count:",
                                 &v808,
                                 &v807,
                                 1LL));
                      v502 = objc_retainAutoreleasedReturnValue(_LSMakeNSErrorImpl(
                                                                  CFSTR("NSOSStatusErrorDomain"),
                                                                  v500,
                                                                  "_LSLaunchWithRunningboard",
                                                                  3090LL,
                                                                  v501));
                      objc_release(v501);
                      v433 = objc_retain(v502);
                      v434 = v772;
                      v772 = v433;
                      goto LABEL_726;
                    }
                    if ( -[NSError code](v729, "code") == 2 )
                    {
                      v433 = 0LL;
                      v434 = v729;
                      v730 = 0LL;
LABEL_726:
                      objc_release(v434);
                      goto LABEL_727;
                    }
                  }
                  v435 = objc_retain(v729);
                  objc_release(v772);
                  goto LABEL_631;
                }
                v407 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideApplicationType](v723, "overrideApplicationType"));
                objc_release(v407);
                v405 = v404;
                if ( v407 )
                {
                  v408 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideApplicationType](v723, "overrideApplicationType"));
                  objc_release(v404);
                  v405 = v408;
                }
              }
              if ( v405 )
              {
                if ( -[NSString isEqual:](v405, "isEqual:", CFSTR("Foreground")) )
                {
                  if ( (v775 & 0x200) != 0 )
                  {
                    if ( (v775 & 0x800000) != 0 )
                      v409 = CFSTR("LaunchRoleLaunchTAL");
                    else
                      v409 = CFSTR("LaunchRoleUserInteractiveNonFocal");
                    v406 = objc_retain(v409);
                    goto LABEL_604;
                  }
                  goto LABEL_603;
                }
                if ( -[NSString isEqual:](v405, "isEqual:", CFSTR("UIElement")) )
                {
LABEL_603:
                  v406 = CFSTR("LaunchRoleUserInteractive");
                  goto LABEL_604;
                }
                if ( -[NSString isEqual:](v405, "isEqual:", CFSTR("BackgroundOnly")) )
                {
                  v406 = CFSTR("LaunchRoleBackground");
                  goto LABEL_604;
                }
              }
              v716 = 0LL;
              goto LABEL_610;
            }
            objc_release(v370);
          }
        }
        objc_release(v345);
        *(v800 + 6) = 0;
        goto LABEL_545;
      }
      v356 = objc_alloc_init(&OBJC_CLASS___NSMutableArray);
      v836 = 0u;
      v837 = 0u;
      memset(v835, 0, sizeof(v835));
      v357 = objc_retain(v349);
      v358 = -[NSArray countByEnumeratingWithState:objects:count:](
               v357,
               "countByEnumeratingWithState:objects:count:",
               v835,
               v822,
               16LL);
      if ( v358 )
      {
        v359 = **&v835[1];
        do
        {
          for ( k = 0LL; k != v358; k = k + 1 )
          {
            if ( **&v835[1] != v359 )
              j__objc_enumerationMutation_0(v357);
            v361 = *(*(&v835[0] + 1) + 8LL * k);
            if ( objc_msgSend(v361, "type") == 16777228 )
              -[NSMutableArray addObject:](v356, "addObject:", v361);
          }
          v358 = -[NSArray countByEnumeratingWithState:objects:count:](
                   v357,
                   "countByEnumeratingWithState:objects:count:",
                   v835,
                   v822,
                   16LL);
        }
        while ( v358 );
      }
      objc_release(v357);
      objc_release(v357);
LABEL_527:
      v349 = v356;
      if ( !v356 )
        goto LABEL_536;
      goto LABEL_528;
    }
LABEL_526:
    v356 = v349;
    goto LABEL_527;
  }
  v345 = 0LL;
LABEL_498:
  v248 = 0LL;
LABEL_822:
  objc_release(v345);
  objc_release(v740);
  objc_release(v758);
  v247 = *(v800 + 6);
LABEL_823:
  if ( v247 == -10652 )
  {
    v573 = v775 & 0xFFFFEFFF;
    v574 = objc_retainAutoreleasedReturnValue(createLaunchModifiers(v775 & 0xFFFFEFFF, a4, v246));
    v575 = v574;
    v768 = v574;
    if ( v574 )
    {
      if ( objc_msgSend(v574, "count") )
      {
        v576 = objc_retain(v575);
        v577 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v576));
        if ( j__os_log_type_enabled_3(v577, OS_LOG_TYPE_INFO) )
        {
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, v835, 0LL);
          v578 = v835[0];
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, 0LL, v835);
          v579 = v835[0];
          asString(v576);
          v580 = (SBYTE7(v835[1]) & 0x80u) == 0 ? v835 : *&v835[0];
          *v822 = 67240962;
          *&v822[4] = v578;
          *&v822[8] = 1026;
          *&v822[10] = v579;
          *&v822[14] = 2048;
          *&v822[16] = v775 & 0xFFFFEFFF;
          *&v822[24] = 2082;
          *&v822[26] = v580;
          j___os_log_impl_1(
            &dword_180981000,
            v577,
            OS_LOG_TYPE_INFO,
            "LAUNCH: Posting launch modifiers to running app 0x%{public}x-0x%{public}x, flags=%lx modifiers=%{public}s",
            v822,
            0x22u);
          if ( SBYTE7(v835[1]) < 0 )
            operator delete(*&v835[0]);
        }
        objc_release(v577);
        v581 = _LSPostLaunchModifiers(4294967294LL, v161, v576);
        LODWORD(v575) = v581 == 0;
        if ( !v581 )
        {
          v582 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v581));
          if ( j__os_log_type_enabled_3(v582, OS_LOG_TYPE_DEBUG) )
          {
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(v161, v835, 0LL);
            v583 = v835[0];
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(v161, 0LL, v835);
            v584 = v835[0];
            asString(v576);
            v585 = (SBYTE7(v835[1]) & 0x80u) == 0 ? v835 : *&v835[0];
            *v822 = 67240962;
            *&v822[4] = v583;
            *&v822[8] = 1026;
            *&v822[10] = v584;
            *&v822[14] = 2048;
            *&v822[16] = v775 & 0xFFFFEFFF;
            *&v822[24] = 2082;
            *&v822[26] = v585;
            j___os_log_impl_1(
              &dword_180981000,
              v582,
              OS_LOG_TYPE_DEBUG,
              "LAUNCH: Posted launch modifiers to running app 0x%{public}x-0x%{public}x, flags=%lx modifiers=%{public}s",
              v822,
              0x22u);
            if ( SBYTE7(v835[1]) < 0 )
              operator delete(*&v835[0]);
          }
          objc_release(v582);
        }
        objc_release(v576);
      }
      else
      {
        LODWORD(v575) = 0;
      }
    }
    v586 = *(*(&v817 + 1) + 24LL);
    v587 = objc_retain(v765);
    v588 = v587;
    if ( (!v587
       || (v589 = objc_retainAutoreleasedReturnValue(-[_LSOpen2Options overrideApplicationType](v587, "overrideApplicationType"))) == 0LL)
      && ((v775 & 0x80000000) == 0 || (v589 = objc_retain(CFSTR("BackgroundOnly"))) == 0LL) )
    {
      v589 = objc_retainAutoreleasedReturnValue(applicationTypeKeyForBundleData(v586));
    }
    objc_release(v588);
    v590 = objc_retain(v589);
    v591 = v590;
    if ( !v161 || !v590 )
    {
LABEL_873:
      objc_release(v591);
      if ( (v775 & 0x1000) != 0 )
        goto LABEL_928;
      IsStopped = applicationIsStopped(v161);
      if ( IsStopped )
      {
        if ( (v775 & 0x2000000) != 0 )
        {
          v622 = objc_retainAutoreleasedReturnValue(_LSOpenLog(IsStopped));
          if ( j__os_log_type_enabled_3(v622, OS_LOG_TYPE_INFO) )
          {
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(v161, v835, 0LL);
            v623 = v835[0];
            LODWORD(v835[0]) = 0;
            _LSASNExtractHighAndLowParts(v161, 0LL, v835);
            *v822 = 67240706;
            *&v822[4] = v623;
            *&v822[8] = 1026;
            *&v822[10] = v835[0];
            *&v822[14] = 2114;
            *&v822[16] = v753;
            j___os_log_impl_1(
              &dword_180981000,
              v622,
              OS_LOG_TYPE_INFO,
              "LAUNCH: Not starting previously launched application because it was launched quarantined, asn=0x%{public}x"
              "-0x%{public}x app=%{public}@",
              v822,
              0x18u);
          }
          goto LABEL_927;
        }
        if ( v161 )
        {
          IsStopped = _LSCopyApplicationInformationItem(4294967294LL, v161, CFSTR("pid"));
          v766 = IsStopped;
          if ( IsStopped )
          {
            v613 = j__CFNumberGetTypeID();
            if ( !v613 || j__CFGetTypeID(v766) == v613 )
            {
              *v822 = 0;
              if ( j__CFNumberGetValue(v766, kCFNumberIntType, v822) )
              {
                v614 = *v822;
                if ( *v822 >= 1 )
                {
                  v615 = -100;
                  while ( j__kill_0(v614, 19) )
                  {
                    v616 = v248;
                    v617 = j____error_10();
                    v618 = *v617;
                    v619 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v617));
                    if ( j__os_log_type_enabled_3(v619, OS_LOG_TYPE_INFO) )
                    {
                      *v822 = 67109376;
                      *&v822[4] = v614;
                      *&v822[8] = 1024;
                      *&v822[10] = v618;
                      j___os_log_impl_1(
                        &dword_180981000,
                        v619,
                        OS_LOG_TYPE_INFO,
                        "LAUNCH: 8837325: Attempting to SIGCONT to pid #%d failed, with errno=#%d, or the process failed "
                        "to actually start",
                        v822,
                        0xEu);
                    }
                    objc_release(v619);
                    if ( v618 != 4 )
                      j__usleep_0(0x2710u);
                    v400 = __CFADD__(v615++, 1);
                    v248 = v616;
                    if ( v400 )
                      goto LABEL_890;
                  }
                  j__CFRelease(v766);
                  goto LABEL_897;
                }
              }
            }
LABEL_890:
            j__CFRelease(v766);
          }
        }
        v620 = objc_retainAutoreleasedReturnValue(_LSOpenLog(IsStopped));
        if ( j__os_log_type_enabled_3(v620, OS_LOG_TYPE_ERROR) )
        {
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, v835, 0LL);
          v621 = v835[0];
          LODWORD(v835[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, 0LL, v835);
          *v822 = 67240706;
          *&v822[4] = v621;
          *&v822[8] = 1026;
          *&v822[10] = v835[0];
          *&v822[14] = 2114;
          *&v822[16] = v753;
          j___os_log_impl_1(
            &dword_180981000,
            v620,
            OS_LOG_TYPE_ERROR,
            "LAUNCH: Unable to start a previously launched but stopped application, asn=0x%{public}x-0x%{public}x app=%{public}@",
            v822,
            0x18u);
        }
        objc_release(v620);
        *(v800 + 6) = -10810;
        goto LABEL_928;
      }
LABEL_897:
      if ( (((v775 & 0x200) == 0) & (v575 ^ 1)) == 0 )
        goto LABEL_928;
      v624 = objc_retainAutoreleasedReturnValue(_LSOpenLog(IsStopped));
      if ( j__os_log_type_enabled_3(v624, OS_LOG_TYPE_DEBUG) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, v835, 0LL);
        v625 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, 0LL, v835);
        *v822 = 67240706;
        *&v822[4] = v625;
        *&v822[8] = 1026;
        *&v822[10] = v835[0];
        *&v822[14] = 2114;
        *&v822[16] = v753;
        j___os_log_impl_1(
          &dword_180981000,
          v624,
          OS_LOG_TYPE_DEBUG,
          "LAUNCH: Make this already-running application bring itself forward, asn=0x%{public}x-0x%{public}x app=%{public}@",
          v822,
          0x18u);
      }
      objc_release(v624);
      if ( a6 && (*v822 = 0, LODWORD(v835[0]) = 0, _LSGetAppleEventClassAndID(a6, v822, v835)) )
      {
        if ( *v822 == 1634039412 && LODWORD(v835[0]) == 1868853091
          || (v626 = 0LL, *v822 == 1196773964) && LODWORD(v835[0]) == 1196773964 )
        {
          v626 = 1024LL;
        }
      }
      else
      {
        v626 = 0LL;
      }
      v627 = _LSSetApplicationInformationItem(
               4294967294LL,
               v161,
               CFSTR("LSApplicationInThrottledStateAfterLaunchKey"),
               &__kCFBooleanFalse,
               0LL);
      IsConnected = CGSServerIsConnected(v627);
      if ( !IsConnected )
      {
        v636 = 0;
        v630 = 0;
LABEL_919:
        if ( !v630 && !v636 )
        {
          if ( (v626 & 0x400) != 0 )
          {
            *&v821[0] = CFSTR("LSDoNotBringAnyWindowsForward)");
            *&v835[0] = &__kCFBooleanTrue;
            IsConnected = objc_retainAutoreleasedReturnValue(
                            +[NSDictionary dictionaryWithObjects:forKeys:count:](
                              &OBJC_CLASS___NSDictionary,
                              "dictionaryWithObjects:forKeys:count:",
                              v835,
                              v821,
                              1LL));
            v622 = IsConnected;
          }
          else
          {
            v622 = 0LL;
          }
          v638 = objc_retainAutoreleasedReturnValue(_LSOpenLog(IsConnected));
          if ( j__os_log_type_enabled_3(v638, OS_LOG_TYPE_DEBUG) )
          {
            LODWORD(v819) = 0;
            _LSASNExtractHighAndLowParts(v161, &v819, 0LL);
            v639 = v819;
            LODWORD(v819) = 0;
            _LSASNExtractHighAndLowParts(v161, 0LL, &v819);
            *v822 = 67240448;
            *&v822[4] = v639;
            *&v822[8] = 1026;
            *&v822[10] = v819;
            j___os_log_impl_1(
              &dword_180981000,
              v638,
              OS_LOG_TYPE_DEBUG,
              "LAUNCH: Application 0x%{public}x-0x%{public}x being sent notification to bring itself forward.",
              v822,
              0xEu);
          }
          objc_release(v638);
          _LSRequestProcessBecomeFrontmost(4294967294LL, v161, v622);
LABEL_927:
          objc_release(v622);
        }
LABEL_928:
        objc_release(v591);
        objc_release(v768);
        if ( !v161 )
          goto LABEL_935;
        goto LABEL_929;
      }
      *&v835[0] = 0LL;
      LODWORD(v835[0]) = _LSASNToUInt64(v161) >> 32;
      DWORD1(v835[0]) = _LSASNToUInt64(v161);
      IsConnected = _CPSSetFrontProcessWithOptions(v835, 0LL, v626);
      v629 = IsConnected;
      v630 = IsConnected == 0;
      if ( IsConnected )
      {
        if ( IsConnected != -13050 )
        {
LABEL_918:
          v636 = v629 == -13050;
          goto LABEL_919;
        }
        v631 = objc_retainAutoreleasedReturnValue(_LSOpenLog(IsConnected));
        if ( j__os_log_type_enabled_3(v631, OS_LOG_TYPE_ERROR) )
        {
          LODWORD(v821[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, v821, 0LL);
          v632 = v821[0];
          LODWORD(v821[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, 0LL, v821);
          *v822 = 67240448;
          *&v822[4] = v632;
          *&v822[8] = 1026;
          *&v822[10] = v821[0];
          v633 = "LAUNCH: Application 0x%{public}x-0x%{public}x is not permitted to be brought to the front at this time.";
          v634 = v631;
          v635 = OS_LOG_TYPE_ERROR;
LABEL_916:
          j___os_log_impl_1(&dword_180981000, v634, v635, v633, v822, 0xEu);
        }
      }
      else
      {
        v631 = objc_retainAutoreleasedReturnValue(_LSOpenLog(IsConnected));
        if ( j__os_log_type_enabled_3(v631, OS_LOG_TYPE_DEBUG) )
        {
          LODWORD(v821[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, v821, 0LL);
          v637 = v821[0];
          LODWORD(v821[0]) = 0;
          _LSASNExtractHighAndLowParts(v161, 0LL, v821);
          *v822 = 67240448;
          *&v822[4] = v637;
          *&v822[8] = 1026;
          *&v822[10] = v821[0];
          v633 = "LAUNCH: Application 0x%{public}x-0x%{public}x made frontmost at this time.";
          v634 = v631;
          v635 = OS_LOG_TYPE_DEBUG;
          goto LABEL_916;
        }
      }
      objc_release(v631);
      goto LABEL_918;
    }
    v592 = _LSCopyApplicationInformationItem(4294967294LL, v161, CFSTR("ApplicationType"));
    if ( -[NSString isEqual:](v591, "isEqual:", v592) )
    {
LABEL_872:
      objc_release(v592);
      goto LABEL_873;
    }
    v593 = _LSCopyApplicationInformationItem(4294967294LL, v161, CFSTR("LSApplicationTypeToRestore"));
    v594 = v593;
    if ( v593 && (v595 = objc_msgSend(v593, "isEqual:", v591), v595) )
    {
      v596 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v595));
      if ( j__os_log_type_enabled_3(v596, OS_LOG_TYPE_INFO) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, v835, 0LL);
        v597 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, 0LL, v835);
        *v822 = 67240962;
        *&v822[4] = v597;
        *&v822[8] = 1026;
        *&v822[10] = v835[0];
        *&v822[14] = 2114;
        *&v822[16] = v591;
        *&v822[24] = 2114;
        *&v822[26] = v592;
        j___os_log_impl_1(
          &dword_180981000,
          v596,
          OS_LOG_TYPE_INFO,
          "LAUNCH:Restoring application 0x%{public}x-0x%{public}x to %{public}@ from %{public}@, because it was launched "
          "with this new application type.",
          v822,
          0x22u);
      }
      objc_release(v596);
      v598 = objc_retainAutoreleasedReturnValue(processManagerFront());
      if ( j__os_log_type_enabled_3(v598, OS_LOG_TYPE_DEFAULT) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, v835, 0LL);
        v599 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, 0LL, v835);
        *v822 = 67240962;
        *&v822[4] = v599;
        *&v822[8] = 1026;
        *&v822[10] = v835[0];
        *&v822[14] = 2114;
        *&v822[16] = v592;
        *&v822[24] = 2114;
        *&v822[26] = v594;
        j___os_log_impl_1(
          &dword_180981000,
          v598,
          OS_LOG_TYPE_DEFAULT,
          "LAUNCHING:0x%{public}x-0x%{public}x restoring application type from %{public}@ to %{public}@",
          v822,
          0x22u);
      }
      objc_release(v598);
      v600 = _LSSetApplicationInformationItem(4294967294LL, v161, CFSTR("ApplicationType"), v594, 0LL);
      if ( !v600 )
        goto LABEL_871;
      v601 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v600));
      if ( !j__os_log_type_enabled_3(v601, OS_LOG_TYPE_ERROR) )
      {
LABEL_870:
        objc_release(v601);
LABEL_871:
        objc_release(v594);
        goto LABEL_872;
      }
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(v161, v835, 0LL);
      v602 = v835[0];
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(v161, 0LL, v835);
      *v822 = 67240962;
      *&v822[4] = v602;
      *&v822[8] = 1026;
      *&v822[10] = v835[0];
      *&v822[14] = 2114;
      *&v822[16] = v594;
      *&v822[24] = 2114;
      *&v822[26] = v592;
      v603 = "LAUNCH: Failed to change app 0x%{public}x-0x%{public}x into type %{public}@, was %{public}@";
    }
    else
    {
      v604 = applicationTypeRank(v591);
      v605 = applicationTypeRank(v592);
      if ( v604 <= v605 )
        goto LABEL_871;
      v606 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v605));
      if ( j__os_log_type_enabled_3(v606, OS_LOG_TYPE_INFO) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, v835, 0LL);
        v607 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, 0LL, v835);
        *v822 = 67240962;
        *&v822[4] = v607;
        *&v822[8] = 1026;
        *&v822[10] = v835[0];
        *&v822[14] = 2114;
        *&v822[16] = v591;
        *&v822[24] = 2114;
        *&v822[26] = v592;
        j___os_log_impl_1(
          &dword_180981000,
          v606,
          OS_LOG_TYPE_INFO,
          "LAUNCH:Changing application 0x%{public}x-0x%{public}x to %{public}@ from %{public}@, because it was launched w"
          "ith this new application type.",
          v822,
          0x22u);
      }
      objc_release(v606);
      v608 = objc_retainAutoreleasedReturnValue(processManagerFront());
      if ( j__os_log_type_enabled_3(v608, OS_LOG_TYPE_DEFAULT) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, v835, 0LL);
        v609 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, 0LL, v835);
        *v822 = 67240962;
        *&v822[4] = v609;
        *&v822[8] = 1026;
        *&v822[10] = v835[0];
        *&v822[14] = 2114;
        *&v822[16] = v591;
        *&v822[24] = 2114;
        *&v822[26] = v592;
        j___os_log_impl_1(
          &dword_180981000,
          v608,
          OS_LOG_TYPE_DEFAULT,
          "LAUNCHING:0x%{public}x-0x%{public}x changing application type to %{public}@ from %{public}@",
          v822,
          0x22u);
      }
      objc_release(v608);
      v610 = _LSSetApplicationInformationItem(4294967294LL, v161, CFSTR("ApplicationType"), v591, 0LL);
      if ( !v610 )
        goto LABEL_871;
      v601 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v610));
      if ( !j__os_log_type_enabled_3(v601, OS_LOG_TYPE_ERROR) )
        goto LABEL_870;
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(v161, v835, 0LL);
      v611 = v835[0];
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(v161, 0LL, v835);
      *v822 = 67240962;
      *&v822[4] = v611;
      *&v822[8] = 1026;
      *&v822[10] = v835[0];
      *&v822[14] = 2114;
      *&v822[16] = v594;
      *&v822[24] = 2114;
      *&v822[26] = v592;
      v603 = "LAUNCH: Failed to promote app 0x%{public}x-0x%{public}x into type %{public}@, was %{public}@";
    }
    j___os_log_impl_1(&dword_180981000, v601, OS_LOG_TYPE_ERROR, v603, v822, 0x22u);
    goto LABEL_870;
  }
  v573 = v775;
  if ( !v161 )
    goto LABEL_935;
LABEL_929:
  if ( (v573 & 0x100) == 0 )
  {
    v806 = v770;
    v640 = objc_retainAutoreleasedReturnValue(+[NSArray arrayWithObjects:count:](&OBJC_CLASS___NSArray, "arrayWithObjects:count:", &v806, 1LL));
    v641 = v640;
    if ( v640 )
    {
      v642 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v640));
      if ( j__os_log_type_enabled_3(v642, OS_LOG_TYPE_DEBUG) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, v835, 0LL);
        v643 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, 0LL, v835);
        v644 = v835[0];
        v645 = objc_retainAutoreleasedReturnValue(objc_msgSend(v770, "URL"));
        *v822 = 67240963;
        *&v822[4] = v643;
        *&v822[8] = 1026;
        *&v822[10] = v644;
        *&v822[14] = 2114;
        *&v822[16] = v753;
        *&v822[24] = 2113;
        *&v822[26] = v645;
        j___os_log_impl_1(
          &dword_180981000,
          v642,
          OS_LOG_TYPE_DEBUG,
          "LAUNCH: Adding asn=0x%{public}x-0x%{public}x %{public}@ node %{private}@ to recents",
          v822,
          0x22u);
        objc_release(v645);
      }
      objc_release(v642);
      _LSAddNodesToRecentsAfterOpening(v641);
    }
    objc_release(v641);
  }
LABEL_935:
  if ( !v248 && v794 )
  {
    v646 = objc_retainAutoreleasedReturnValue(objc_msgSend(v761, "URL"));
    SecTranslocateDeleteSecureDirectory();
    objc_release(v646);
  }
  v647 = *(v800 + 6);
  if ( !v647 )
  {
    v648 = objc_autoreleasePoolPush();
    v649 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v648));
    if ( j__os_log_type_enabled_3(v649, OS_LOG_TYPE_DEBUG) )
    {
      v650 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
      *v822 = 138543619;
      *&v822[4] = v753;
      *&v822[12] = 2113;
      *&v822[14] = v650;
      j___os_log_impl_1(
        &dword_180981000,
        v649,
        OS_LOG_TYPE_DEBUG,
        "LAUNCH: Updating trust expiration for %{public}@ %{private}@.",
        v822,
        0x16u);
      objc_release(v650);
    }
    objc_release(v649);
    v651 = objc_retainAutoreleasedReturnValue(+[_LSDService XPCProxyWithErrorHandler:](
                                                &OBJC_CLASS____LSDTrustedSignatureService,
                                                0LL));
    v652 = objc_retainAutoreleasedReturnValue(objc_msgSend(v769, "URL"));
    objc_msgSend(v651, "updateTrustExpirationDateForURL:", v652);
    objc_release(v652);
    objc_release(v651);
    objc_autoreleasePoolPop(v648);
    v647 = *(v800 + 6);
  }
  if ( v647 || (v775 & 0x1000) != 0 || (v775 & 0x2000000) != 0 || v573 == 1 || (v573 & 0x10000) != 0 )
    goto LABEL_960;
  v653 = -[_LSOpen2Options skipWaitForCheckIn](v765, "skipWaitForCheckIn");
  if ( !v653 )
  {
    v657 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v653));
    if ( j__os_log_type_enabled_3(v657, OS_LOG_TYPE_DEBUG) )
    {
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(v161, v835, 0LL);
      v658 = v835[0];
      LODWORD(v835[0]) = 0;
      _LSASNExtractHighAndLowParts(v161, 0LL, v835);
      *v822 = 67240448;
      *&v822[4] = v658;
      *&v822[8] = 1026;
      *&v822[10] = v835[0];
      j___os_log_impl_1(
        &dword_180981000,
        v657,
        OS_LOG_TYPE_DEBUG,
        "LAUNCH: Waiting for application 0x%{public}x-0x%{public}x to finish launching",
        v822,
        0xEu);
    }
    objc_release(v657);
    v659 = _LSWaitForApplicationCheckIn(4294967294LL, v161);
    if ( v659 )
    {
      v660 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v659));
      if ( j__os_log_type_enabled_3(v660, OS_LOG_TYPE_ERROR) )
      {
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, v835, 0LL);
        v661 = v835[0];
        LODWORD(v835[0]) = 0;
        _LSASNExtractHighAndLowParts(v161, 0LL, v835);
        *v822 = 67240448;
        *&v822[4] = v661;
        *&v822[8] = 1026;
        *&v822[10] = v835[0];
        j___os_log_impl_1(
          &dword_180981000,
          v660,
          OS_LOG_TYPE_ERROR,
          "LAUNCH: Timed-out waiting for launch of application 0x%{public}x-0x%{public}x.",
          v822,
          0xEu);
      }
      objc_release(v660);
    }
    v654 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v659));
    if ( !j__os_log_type_enabled_3(v654, OS_LOG_TYPE_DEBUG) )
      goto LABEL_959;
    LODWORD(v835[0]) = 0;
    _LSASNExtractHighAndLowParts(v161, v835, 0LL);
    v662 = v835[0];
    LODWORD(v835[0]) = 0;
    _LSASNExtractHighAndLowParts(v161, 0LL, v835);
    *v822 = 67240448;
    *&v822[4] = v662;
    *&v822[8] = 1026;
    *&v822[10] = v835[0];
    v656 = "LAUNCH: Completed waiting for application 0x%{public}x-0x%{public}x to finish launching";
    goto LABEL_958;
  }
  v654 = objc_retainAutoreleasedReturnValue(_LSOpenLog(v653));
  if ( j__os_log_type_enabled_3(v654, OS_LOG_TYPE_DEBUG) )
  {
    LODWORD(v835[0]) = 0;
    _LSASNExtractHighAndLowParts(v161, v835, 0LL);
    v655 = v835[0];
    LODWORD(v835[0]) = 0;
    _LSASNExtractHighAndLowParts(v161, 0LL, v835);
    *v822 = 67240448;
    *&v822[4] = v655;
    *&v822[8] = 1026;
    *&v822[10] = v835[0];
    v656 = "LAUNCH: Skipping check-in wait for application 0x%{public}x-0x%{public}x because caller asked us not to do so";
LABEL_958:
    j___os_log_impl_1(&dword_180981000, v654, OS_LOG_TYPE_DEBUG, v656, v822, 0xEu);
  }
LABEL_959:
  objc_release(v654);
LABEL_960:
  if ( a13 )
    _LSASNExtractHighAndLowParts(v161, a13, a13 + 4);
  j___Block_object_dispose_6(&v815, 8);
  objc_release(v750);
  objc_release(v754);
  objc_release(v753);
  j___Block_object_dispose_6(&v817, 8);
LABEL_963:
  if ( a14 )
    *a14 = objc_retainAutorelease(v772);
  v663 = *(v800 + 6);
  objc_release(v761);
  objc_release(v769);
  if ( v161 )
    j__CFRelease(v161);
  objc_release(v756);
  objc_release(v770);
  objc_release(v772);
  objc_release(v763);
  j___Block_object_dispose_6(&v795, 8);
  j___Block_object_dispose_6(&v799, 8);
  objc_release(v765);
  objc_release(v764);
  objc_release(v770);
  return v663;
}