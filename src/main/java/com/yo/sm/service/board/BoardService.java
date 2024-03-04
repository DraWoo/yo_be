package com.yo.sm.service.board;

import com.yo.sm.model.dto.board.BoardDto;

import java.util.List;

public interface BoardService {
    BoardDto saveBoard(BoardDto boardDto); // saveBoard 메서드를 BoardDto를 사용하도록 변경
    List<BoardDto> getAllBoards();
    BoardDto getBoardById(Long id);
    BoardDto updateBoard(Long id, BoardDto boardDto);
    void deleteBoard(Long id);
}


