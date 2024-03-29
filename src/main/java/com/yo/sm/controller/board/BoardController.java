package com.yo.sm.controller.board;

import com.yo.sm.model.ApiResult;
import com.yo.sm.model.ApiResultCode;
import com.yo.sm.model.dto.board.BoardDto;

import javax.annotation.Resource;

import com.yo.sm.service.board.BoardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/boards")
@Tag(name= "Board API", description = "Board 관련 API")
@Slf4j
public class BoardController {

    @Resource
    private BoardService boardService;

    /**
     * 새 게시물을 저장하는 API를 처리하는 메소드입니다.
     *
     * @param boardDto 클라이언트에서 전송된 게시물 데이터가 담긴 DTO 객체입니다.
     * @return ResponseEntity<ApiResult<BoardDto>> HTTP 응답 객체로,
     * 요청이 성공하면 HTTP 상태 코드 200(OK)과 함께 저장된 게시물 정보를 담은 ApiResult 객체를 응답 바디에 포함하여 반환합니다.
     */
    @PostMapping("/posts")
    @Operation(summary = "새 게시물 저장", description  = "새로운 게시물을 저장합니다.")
    public ResponseEntity<ApiResult<BoardDto>> saveBoard(@RequestBody BoardDto boardDto) {
        log.info("요청");
        BoardDto savedBoard = boardService.saveBoard(boardDto);
        ApiResult<BoardDto> response = ApiResult.<BoardDto>builder()
                .code(ApiResultCode.succeed)
                .payload(savedBoard)
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping
    @Operation(summary = "모든 게시물 조회", description  = "저장된 모든 게시물을 조회합니다.")
    public ResponseEntity<ApiResult<List<BoardDto>>> getAllBoards() {
        List<BoardDto> boards = boardService.getAllBoards();
        ApiResult<List<BoardDto>> response = ApiResult.<List<BoardDto>>builder()
                .code(ApiResultCode.succeed)
                .payload(boards)
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/{id}")
    @Operation(summary = "특정 게시물 정보 조회", description  = "게시물 ID를 통해 특정 게시물의 정보를 조회합니다.")
    public ResponseEntity<ApiResult<BoardDto>> getBoardById(@PathVariable Long id) {
        BoardDto boardDto = boardService.getBoardById(id);
        ApiResult<BoardDto> response = ApiResult.<BoardDto>builder()
                .code(ApiResultCode.succeed)
                .payload(boardDto)
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PutMapping("/{id}")
    @Operation(summary = "게시물 정보 업데이트", description  = "지정된 ID의 게시물 정보를 업데이트합니다.")
    public ResponseEntity<ApiResult<BoardDto>> updateBoard(@PathVariable Long id, @RequestBody BoardDto boardDto) {
        BoardDto updatedBoard = boardService.updateBoard(id, boardDto);
        ApiResult<BoardDto> response = ApiResult.<BoardDto>builder()
                .code(ApiResultCode.succeed)
                .payload(updatedBoard)
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "게시물 삭제", description  = "지정된 ID의 게시물을 삭제합니다.")
    public ResponseEntity<ApiResult<Void>> deleteBoard(@PathVariable Long id) {
        boardService.deleteBoard(id);
        ApiResult<Void> response = ApiResult.<Void>builder()
                .code(ApiResultCode.succeed)
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
